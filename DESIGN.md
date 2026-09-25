# Design: in-pod eBPF CLAT as a chained Cilium CNI plugin

Sep 25, 2026 · @Andrea Bedini

## Context and goals

Decision: replace the per-pod CLAT sidecars with a chained CNI plugin, `cilium-clat`. The plugin attaches a stateless eBPF CLAT (RFC 6877, RFC 7915) to the pod-side `eth0`. Cilium stays unmodified.

The cluster runs Cilium in IPv6-only mode on Talos. Some workloads need IPv4: IPv4 literals, IPv4-only sockets, or software that ignores AAAA records. Today each such pod carries a CLAT sidecar. The sidecars add a container, a daemon, and a privilege (`NET_ADMIN`) to every affected pod.

Goals:

- Every pod gets a working IPv4 stack with no change to its spec.
- No userspace process per pod. The translator lives and dies with the pod network namespace.
- No fork of Cilium and no custom Talos kernel.
- Cilium sees only IPv6 from the endpoint address. Anti-spoofing, identity, and policy keep working.
- Correct ICMP error translation, so PMTUD and traceroute work over IPv4.

## Non-goals

- **No PLAT.** The router keeps the NAT64 function. This design only adds the customer-side translator.
- **No inbound IPv4.** Pods do not accept connections to an IPv4 address. Services stay IPv6.
- **No pod-to-pod IPv4.** Every pod has the same IPv4 address, `192.0.0.2`. IPv4 is for egress to the IPv4 internet only.
- **No upstream Cilium change.** If the design proves out, a Cilium proposal (CFP) is a separate decision.
- **No netkit datapath in phase 1.** Phase 1 supports veth only. See [Interaction with Cilium](#interaction-with-cilium).

## Architecture overview

The system has four components. Only the router PLAT exists today.

| Component | Form | Runs where | Lifetime |
| --- | --- | --- | --- |
| `cilium-clat` CNI plugin | Static Go binary, BPF object embedded with `bpf2go` | Host, called by the container runtime | Per CNI call |
| CLAT BPF programs | `clat_egress`, `clat_ingress` on clsact | Pod netns, pod-side `eth0` | Pod netns |
| Installer | DaemonSet, init container copies binary and conflist | Every node | Node |
| PLAT | Stateless or stateful NAT64 | Router | Permanent |

```mermaid
flowchart LR
    subgraph Pod netns
        app[App IPv4 socket] --> eth0[eth0<br/>192.0.0.2 + pod IPv6]
        eth0 -.clsact egress.-> clatE[clat_egress<br/>v4 to v6]
    end
    clatE --> lxc[lxc veth<br/>Cilium from-container]
    lxc --> node[Node routing]
    node --> plat[Router PLAT<br/>v6 to v4]
    plat --> inet[IPv4 internet]
```

The plugin runs after `cilium-cni` in the chain. It configures the pod netns once and exits. After that, the kernel does all the work. No component on the node needs to stay running for existing pods to keep IPv4.

## Packet flow

The CLAT maps one IPv4 host to the pod's own IPv6 address. Destinations map into the CLAT prefix `P` (see [Address and prefix plan](#address-and-prefix-plan)).

| Direction | Field | Before | After |
| --- | --- | --- | --- |
| Egress (clsact egress, pod `eth0`) | Source | `192.0.0.2` | Pod IPv6 address |
| Egress | Destination | `a.b.c.d` | `P::a.b.c.d` (RFC 6052, /96) |
| Ingress (clsact ingress, pod `eth0`) | Source | `P::a.b.c.d` | `a.b.c.d` |
| Ingress | Destination | Pod IPv6 address | `192.0.0.2` |

```mermaid
sequenceDiagram
    participant App
    participant CLAT as clat_egress / clat_ingress
    participant Cilium as Cilium lxc (host side)
    participant PLAT as Router PLAT
    App->>CLAT: IPv4 192.0.0.2 to a.b.c.d
    CLAT->>Cilium: IPv6 pod addr to P::a.b.c.d
    Cilium->>PLAT: policy, routing, masquerade off
    PLAT-->>Cilium: IPv6 P::a.b.c.d to pod addr
    Cilium-->>CLAT: bpf_redirect_peer to pod eth0
    CLAT-->>App: IPv4 a.b.c.d to 192.0.0.2
```

Ingress translation matches only packets whose source is inside `P` and whose destination is the pod address. All other IPv6 traffic passes untouched. This match rule is the reason `P` must not overlap the DNS64 prefix.

## Address and prefix plan

Recommendation: use a dedicated CLAT prefix `P = 64:ff9b:1::/96` from the RFC 8215 local-use range. Keep `64:ff9b::/96` for DNS64 and the existing tayga PLAT.

| Item | Value | Why |
| --- | --- | --- |
| Pod IPv4 | `192.0.0.2/29` on `eth0` | RFC 7335 IPv4 service continuity prefix. Same value in every pod. |
| IPv4 gateway | `192.0.0.1`, permanent neighbour entry | No ARP responder exists on the Cilium side in IPv6-only mode. |
| CLAT source | Pod IPv6 address | Cilium anti-spoofing drops any other source. |
| CLAT prefix `P` | `64:ff9b:1::/96` | Keeps CLAT return traffic apart from DNS64 traffic. |
| DNS64 / PLAT prefix | `64:ff9b::/96` (current tayga) | Unchanged. |

### Why `P` must differ from the DNS64 prefix

The CLAT uses the pod address as its source. So do native IPv6 sockets in the same pod. If an app connects over IPv6 to a DNS64 address `64:ff9b::a.b.c.d`, the reply is identical to CLAT return traffic. With a shared prefix, `clat_ingress` translates that reply to IPv4. The kernel finds no IPv4 socket and sends a reset.

| Option | Router change | Cost |
| --- | --- | --- |
| **A. Separate `P` (recommended)** | PLAT also serves `64:ff9b:1::/96` | tayga takes one prefix, so a second tayga instance or a move to Jool NAT64 |
| B. Shared prefix, no DNS64 in cluster | None | Remove `dns64` from CoreDNS. IPv6-only pods without CLAT lose IPv4 reach. |
| C. Shared prefix, flow state in CLAT | None | LRU map of outbound IPv4 flows. More code, map sizing, stateful behaviour. |

### PLAT pool pressure

The tayga dynamic pool gives one IPv4 address to each IPv6 source. Each pod address uses one entry until it times out. Pod churn can exhaust a small pool.

Two mitigations:

- Enable Cilium IPv6 masquerade toward `P`. The PLAT then sees one source per node. Cilium reverses the SNAT before `clat_ingress` runs, so the CLAT match still works.
- Replace tayga with a stateful NAT64 (Jool NAT64) that masquerades to one IPv4 address.

## CNI plugin specification

The plugin is a CNI 1.0 chained plugin. It must run after `cilium-cni` and needs `prevResult`.

### Configuration

```json
{
  "cniVersion": "1.0.0",
  "name": "cilium",
  "plugins": [
    { "type": "cilium-cni" },
    {
      "type": "cilium-clat",
      "clatPrefix": "64:ff9b:1::/96",
      "podIPv4": "192.0.0.2/29",
      "gatewayIPv4": "192.0.0.1",
      "excludeNamespaces": ["kube-system"],
      "logFile": "/var/log/cilium-clat.log"
    }
  ]
}
```

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `clatPrefix` | IPv6 /96 | required | Prefix `P` for destination mapping |
| `podIPv4` | IPv4 CIDR | `192.0.0.2/29` | Address set on pod `eth0` |
| `gatewayIPv4` | IPv4 | `192.0.0.1` | Next hop for the IPv4 default route |
| `excludeNamespaces` | list | `[]` | Namespaces that get no CLAT (from `K8S_POD_NAMESPACE` in `CNI_ARGS`) |
| `logFile` | path | none | Plugin log. The plugin never writes to stdout except the result. |

### ADD

1. Parse `prevResult`. Stop and pass it through unchanged if any condition is true:
   - The pod has no IPv6 address.
   - The pod already has an IPv4 address (dual-stack).
   - The namespace is excluded.
2. Find the host-side peer of `eth0` from its link index. Read the peer MAC in the host netns.
3. Enter the pod netns and apply:

   ```sh
   ip addr add 192.0.0.2/29 dev eth0 noprefixroute
   ip neigh replace 192.0.0.1 lladdr "$PEER_MAC" dev eth0 nud permanent
   ip route replace 192.0.0.1/32 dev eth0 scope link
   ip route replace default via 192.0.0.1 dev eth0 mtu $((ETH0_MTU - 20))
   ```
4. Load the BPF object. Set the per-pod constants in `.rodata`: `P`, pod IPv6 address, pod IPv4 address.
5. Add a `clsact` qdisc on `eth0`. Attach `clat_egress` and `clat_ingress` as direct-action filters.
6. Return `prevResult` **unchanged**.

Do not add `192.0.0.2` to the result. The runtime reports result IPs to the kubelet as pod IPs. An IPv4 pod IP in an IPv6-only cluster breaks `status.podIPs` and Services.

### Attachment: clsact, not tcx

Phase 1 uses netlink-attached `cls_bpf` on `clsact`. The kernel owns the attachment, and it disappears with `eth0`. tcx attachments are held by a link fd. The plugin exits after ADD, so a tcx link needs a bpffs pin, and DEL and a garbage collector must remove it. Nothing else shares the pod-side `eth0`, so tcx ordering brings no benefit here.

### DEL

DEL is idempotent and never fails. The netns can already be gone. When it exists, remove the filters, qdisc, route, neighbour entry, and address. When it does not, do nothing.

### CHECK

CHECK verifies the address, default route, neighbour entry, and both filters with the expected program tag. It returns an error on any mismatch.

## eBPF program design

Two stateless programs translate per RFC 7915. The reference implementation to port is the CLAT BPF program in NetworkManager 1.58, because it already handles fragments and ICMP error payloads. Android `clatd.c` is simpler, but it relies on a userspace fallback that this design does not have.

### Per-pod constants

The plugin sets these in `.rodata` before load. The verifier then treats them as known values, and each pod gets its own program instance.

```c
volatile const struct in6_addr clat_prefix;   /* P, low 32 bits zero */
volatile const struct in6_addr pod_ip6;
volatile const __be32          pod_ip4;       /* 192.0.0.2 */
```

### Header translation

| Field | IPv4 to IPv6 (egress) | IPv6 to IPv4 (ingress) |
| --- | --- | --- |
| Protocol switch | `bpf_skb_change_proto(skb, htons(ETH_P_IPV6), 0)` | `bpf_skb_change_proto(skb, htons(ETH_P_IP), 0)` |
| TOS / traffic class | Copy | Copy |
| Flow label | 0 | Ignore |
| TTL / hop limit | Copy, no decrement | Copy, no decrement |
| Protocol / next header | ICMP 1 becomes 58 | 58 becomes 1 |
| IPv4 options | Drop packets with source-route options, else ignore | Not applicable |
| IPv6 extension headers | Not applicable | Fragment header only. Drop others. |
| IPv4 header checksum | Not applicable | Compute |
| Ethernet type | Rewrite `h_proto` | Rewrite `h_proto` |

The CLAT is local to the host, so it does not decrement TTL. Cilium does its own hop handling on the host side.

### Checksums

- **TCP and UDP.** Only the pseudo-header changes. Update with `bpf_l4_csum_replace(..., BPF_F_PSEUDO_HDR)` per changed address word. This is correct for `CHECKSUM_PARTIAL`, which is the normal case on veth egress: the field holds only the pseudo-header sum.
- **UDP with checksum 0.** Zero is illegal in IPv6. Compute the full checksum on egress. Drop fragmented zero-checksum UDP, because the whole datagram is not available.
- **ICMP.** ICMPv6 includes a pseudo-header and ICMPv4 does not. Apply the type change and the pseudo-header difference with `bpf_csum_diff`.

### Offloads

`bpf_skb_change_proto` converts the TCP GSO type and adjusts `gso_size` by the 20-byte header difference. Other GSO types can be refused by the helper. The program drops refused packets and counts them. Confirm UDP GSO behaviour on the Talos kernel before release.

### Fragments

- Egress: an IPv4 fragment (MF set or offset not 0) gets an IPv6 Fragment header. Identification is the IPv4 ID, zero-extended. Only the first fragment carries the L4 header for checksum update.
- Ingress: a Fragment header becomes IPv4 MF and offset. Set DF to 0.
- Unfragmented egress with DF 0 gets no Fragment header.

### ICMP

| IPv6 in (ingress) | IPv4 out |
| --- | --- |
| Echo Reply 129 | Echo Reply 0 |
| Packet Too Big 2 | Dest Unreachable 3, code 4, MTU minus 20 |
| Time Exceeded 3 | Time Exceeded 11 |
| Dest Unreachable 1, code 4 (port) | Dest Unreachable 3, code 3 |
| Dest Unreachable 1, other codes | Dest Unreachable 3, code 1 |
| Parameter Problem 4 | Parameter Problem 12, pointer mapped, or drop |

For error messages the program also translates the embedded header. The inner IPv6 header shrinks by 20 bytes. The program moves the payload with `bpf_skb_adjust_room` and recomputes the inner and outer checksums. Egress direction handles Echo Request 8 to 128. Egress ICMP errors are rare because the pod accepts no inbound IPv4 flows. Phase 1 drops them.

### Maps

The programs keep no flow state. One `BPF_MAP_TYPE_PERCPU_ARRAY` holds counters: translated packets per direction, and drops per reason. The plugin pins nothing. Counters are read through `bpftool map dump` in the pod netns, or through the metrics exporter in [Open questions](#open-questions).

## Interaction with Cilium

Cilium sees plain IPv6 from a known endpoint to `P::a.b.c.d`. Most Cilium features work unchanged. The exceptions are in the table.

| Cilium feature | Effect | Action |
| --- | --- | --- |
| Source anti-spoofing | Passes: source is the endpoint address | None |
| Identity | Destination `P::/96` resolves to the `world` identity | None |
| `toCIDR` policy | IPv4 CIDRs never match | Write IPv4 ranges inside `P`, e.g. `1.2.3.0/24` becomes `64:ff9b:1::102:300/120` |
| `toFQDNs` policy | DNS proxy learns A records, datapath sees `P::a.b.c.d`. No match. | Allow `P::/96` by CIDR for CLAT pods. See [Open questions](#open-questions). |
| Hubble | Flows show IPv6 destinations in `P` | Decode the low 32 bits in dashboards |
| IPv6 masquerade | If on, the PLAT sees node addresses | Make sure `P` is not in the non-masquerade list |
| Socket LB | IPv4 hooks are absent in IPv6-only mode | None. No IPv4 Services exist. |
| Agent restart, endpoint regeneration | Host-side programs reload. Pod-side `clsact` is untouched. | None |
| Pod `eth0` MTU | Set by Cilium | The plugin reads it and sets the IPv4 route MTU to `MTU - 20` |

### Datapath mode

Phase 1 requires the veth datapath (`bpf.datapathMode=veth`, the default). With netkit, BPF programs for the peer are attached from the primary side, and Cilium owns that side. Support for netkit needs a Cilium change and is out of scope.

### Delivery with `bpf_redirect_peer`

With BPF host routing, Cilium delivers to the pod with `bpf_redirect_peer`. The skb then goes through ingress processing on the peer device again, so `clat_ingress` should run. This is an assumption to verify in the [test plan](#test-and-validation-plan). If it fails, every IPv4 reply is lost, and the pod sees IPv6 packets it does not expect.

## Deployment on Talos

The design needs no Talos system extension. The kernel options it uses (`CONFIG_NET_SCH_INGRESS`, `CONFIG_NET_CLS_BPF`, `CONFIG_BPF_SYSCALL`) are already required by Cilium. The programs only access `__sk_buff` and packet data, so they need no CO-RE or BTF.

### Cilium Helm values

```yaml
cni:
  customConf: true
  configMap: cni-configuration   # holds the conflist from the plugin specification
  exclusive: true                # Cilium still owns /etc/cni/net.d
```

### Installer DaemonSet

- `hostNetwork: true`. The installer must not depend on the CNI it installs.
- Tolerate all taints, including `node.kubernetes.io/not-ready`.
- An init container copies `cilium-clat` to the host `/opt/cni/bin` through a `hostPath` mount, then the pod sleeps. This is the same mechanism Cilium uses for `cilium-cni`.
- Copy to a temporary name, then `rename(2)`. The runtime must never execute a partial binary.

### Boot ordering

Cilium writes the chained conflist before the installer has run. Until the binary exists, every pod sandbox ADD fails and the runtime retries. The failure is self-healing, but it delays cluster start. On a single-node cluster this affects every pod after each reboot, if `/opt/cni/bin` is not persistent. Measure the delay. If it is too long, bake the binary into the Cilium agent image instead.

### Migration from sidecars

1. Deploy with `excludeNamespaces` listing every namespace that still runs sidecars. A sidecar and the plugin would both install an IPv4 default route.
2. For each namespace: remove the sidecar, remove the namespace from `excludeNamespaces`, restart the workloads.
3. Delete the sidecar image and its `NET_ADMIN` grants.

## Failure modes and mitigations

| Failure | Symptom | Mitigation |
| --- | --- | --- |
| `P` overlaps DNS64 prefix | IPv6 connections to DNS64 names get RST | Separate `P` (address plan, option A) |
| `clat_ingress` skipped by `bpf_redirect_peer` | IPv4 connects time out, no replies | Test gate before rollout. Fall back to host-side delivery through the stack. |
| ICMP error translation bug | PMTUD black holes: small requests work, large responses hang | Route MTU `MTU - 20`. Test with a forced low PLAT MTU. |
| Non-TCP GSO refused by helper | Large UDP sends drop | Drop counter. Disable UDP GSO in affected apps. |
| PLAT dynamic pool exhausted | New IPv4 flows fail for some pods only | IPv6 masquerade or stateful NAT64 |
| Plugin binary missing | Pod sandbox ADD fails | Installer DaemonSet, atomic copy |
| BPF load fails (verifier) | ADD fails, pod never starts | CI loads the object on the Talos kernel version. Optional fail-open mode: skip the CLAT and log. |
| `toFQDNs` policy on a CLAT pod | IPv4 egress denied by policy | CIDR policy on `P` |
| Sidecar and plugin both active | Two IPv4 default routes, unstable egress | `excludeNamespaces` during migration |

Fail-closed is the default. A pod that asks for IPv4 and silently lacks it is harder to debug than a pod that does not start.

## Test and validation plan

Testing runs in three layers. Each layer must pass before the next starts.

### 1. Program tests with `BPF_PROG_TEST_RUN`

Feed crafted packets to each program and compare the output bytes. Run on Fedora and on the Talos kernel version.

- **Differential oracle:** translate the same packets with `jool_siit` in a scratch netns. Jool follows RFC 7915 closely, so any byte difference is a bug in one of the two.
- Cases: TCP SYN, UDP, UDP with checksum 0, echo request and reply, each ICMP error type with an embedded TCP and UDP header, first and later fragments, IPv4 options, IPv6 extension headers, TTL 1.
- Checksum cases for `CHECKSUM_PARTIAL`, `CHECKSUM_COMPLETE`, and `CHECKSUM_NONE`. `BPF_PROG_TEST_RUN` does not model all of these, so layer 2 covers the rest.

### 2. Netns integration on Fedora, no Cilium

A veth pair between a "pod" netns and a "node" netns, plus a PLAT netns with `64:ff9b:1::/96`. Run the plugin binary directly with a synthetic `prevResult`.

```sh
ip netns exec pod curl -4 http://198.51.100.10/
ip netns exec pod ping -4 -s 3000 198.51.100.10    # fragments
ip netns exec pod tracepath -4 198.51.100.10       # PMTUD, PLAT link MTU 1280
ip netns exec pod iperf3 -4 -c 198.51.100.10 -t 30 # GSO, GRO paths
```

### 3. Cluster tests

- **Gate:** confirm `clat_ingress` runs after `bpf_redirect_peer`. Check the ingress counter in the pod netns while `curl -4` succeeds.
- IPv4 literal egress, `traceroute -4`, large download for PMTUD.
- Native IPv6 to a DNS64 name from the same pod still works.
- Cilium agent restart during a long IPv4 download: the flow survives.
- Pod delete: no leftover qdisc, filter, or bpffs entry on the node.
- 100 pod churn cycles: no ADD or DEL errors, PLAT pool stays within bounds.

## Alternatives considered

| Alternative | Why not chosen |
| --- | --- |
| Keep CLAT sidecars (status quo) | A daemon, a container, and `NET_ADMIN` per pod. Pod specs must opt in. |
| Patch Cilium `bpf_lxc.c` | Fork of datapath and agent, rebased each minor release. IPAM and ARP changes for an IPv4 address in IPv6-only mode. Worth it only as an upstream proposal. |
| Jool SIIT per netns from the plugin | Out-of-tree module. Talos enforces module signing with a per-build key, so it needs a custom kernel and installer. |
| DS-Lite (`ip6tnl mode ipip6`) per pod | Needs an AFTR on the router. All pods share `192.0.0.2`, so the AFTR NAT44 collides unless each pod gets a unique IPv4 address. Cilium policy sees one IPv6 destination for all IPv4 traffic. |
| tcx instead of `clsact` | Link fds need bpffs pins, DEL cleanup, and garbage collection. No ordering benefit on the pod-side device. Possible later change. |
| Cilium NAT46x64 gateway | PLAT function, not CLAT. Does not give the pod an IPv4 stack. |

## Open questions

- [ ] Pod IPv6 addressing: are pod addresses routed GUA from `2403:580e:e231::/48`, or masqueraded? This decides whether the PLAT sees one source per pod or per node.
- [ ] PLAT for `P`: a second tayga instance, or move the router to Jool NAT64 with both prefixes?
- [ ] License of the NetworkManager CLAT BPF source. Confirm it permits a port into this plugin.
- [ ] `toFQDNs`: is FQDN policy needed for CLAT pods at all? If yes, investigate a DNS proxy hook that also adds `P::a.b.c.d` for each A record.
- [ ] Metrics: a small exporter in the installer DaemonSet that walks pod netns and reads the counter maps, or `bpftool` only?
- [ ] Opt-in per pod through an annotation, which needs an API call from the plugin, or namespace exclusion only?
- [ ] Fail-open mode: keep it at all?

## Sources

- [NetworkManager eBPF CLAT, Red Hat Developer](https://developers.redhat.com/articles/2026/07/08/networkmanager-supports-ipv6-mostly)
- [RFC 6877: 464XLAT](https://www.rfc-editor.org/rfc/rfc6877)
- [RFC 7915: IP/ICMP translation algorithm](https://www.rfc-editor.org/rfc/rfc7915)
- [RFC 6052: IPv6 addressing of IPv4/IPv6 translators](https://www.rfc-editor.org/rfc/rfc6052)
- [RFC 7335: IPv4 service continuity prefix](https://www.rfc-editor.org/rfc/rfc7335)
- [RFC 8215: local-use IPv4/IPv6 translation prefix](https://www.rfc-editor.org/rfc/rfc8215)
- [CNI specification 1.0](https://www.cni.dev/docs/spec/)
