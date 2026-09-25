#!/usr/bin/env bash
# Layer-2 integration test: the plugin on a veth pair between three network
# namespaces, no Cilium and no NAT64.
#
#   pod (eth0) ---- node (lxc0 / srv0) ---- srv (eth0)
#
# The server owns 64:ff9b:1::198.51.100.10 directly, so IPv4 traffic from the
# pod is answered without a PLAT. That exercises both translation directions,
# fragments, PMTUD and ICMP errors.
#
# Needs root, iproute2, curl, ping, tracepath, python3. Run from the repo root:
#   sudo hack/netns-test.sh            # full test
#   sudo hack/netns-test.sh --no-clat  # only the IPv6 topology (harness check)
set -eu

BIN="${BIN:-$(pwd)/bin/cilium-clat}"
PREFIX="64:ff9b:1::"
SRV4="198.51.100.10"
SRV6="${PREFIX}c633:640a"     # 198.51.100.10 in hex
POD6="2001:db8:1::2"
NODE_POD6="2001:db8:1::1"
NODE_SRV6="2001:db8:2::1"
SRV_LINK6="2001:db8:2::2"
PORT=8080
NO_CLAT=0
[ "${1:-}" = "--no-clat" ] && NO_CLAT=1

log() { printf '\n==> %s\n' "$*"; }
dump_state() {
	[ "$NO_CLAT" -eq 1 ] && return 0
	printf '\n--- CLAT counters ---\n'
	"$BIN" counters --netns /run/netns/pod 2>&1 || true
	printf '\n--- plugin log ---\n'
	cat "$WORK/cilium-clat.log" 2>/dev/null || true
	printf '\n--- pod interface stats ---\n'
	ip -n pod -s link show eth0 2>/dev/null || true
}
fail() { printf 'FAIL: %s\n' "$*" >&2; dump_state; exit 1; }

cleanup() {
	set +e
	[ -n "${HTTP_PID:-}" ] && kill "$HTTP_PID" 2>/dev/null
	[ -n "${UDP_PID:-}" ] && kill "$UDP_PID" 2>/dev/null
	for n in pod node srv; do ip netns del "$n" 2>/dev/null; done
	rm -rf "$WORK"
}
trap cleanup EXIT
WORK="$(mktemp -d)"

[ "$(id -u)" -eq 0 ] || fail "run as root"
if [ "$NO_CLAT" -eq 0 ]; then
	[ -x "$BIN" ] || fail "plugin binary $BIN not found, run: mise run build"
fi

log "topology"
ip netns add pod
ip netns add node
ip netns add srv
ip link add eth0 netns pod type veth peer name lxc0 netns node
ip link add eth0 netns srv type veth peer name srv0 netns node
for n in pod node srv; do
	ip -n "$n" link set lo up
	ip netns exec "$n" sysctl -qw net.ipv6.conf.all.forwarding=1
	ip netns exec "$n" sysctl -qw net.ipv6.conf.default.accept_dad=0
	ip netns exec "$n" sysctl -qw net.ipv6.conf.all.accept_dad=0
done
ip -n pod link set eth0 up
ip -n node link set lxc0 up
ip -n node link set srv0 up
ip -n srv link set eth0 up

ip -n pod addr add "$POD6/64" dev eth0 nodad
ip -n node addr add "$NODE_POD6/64" dev lxc0 nodad
ip -n node addr add "$NODE_SRV6/64" dev srv0 nodad
ip -n srv addr add "$SRV_LINK6/64" dev eth0 nodad
ip -n srv addr add "$SRV6/128" dev eth0 nodad
ip -n pod route add default via "$NODE_POD6" dev eth0
ip -n srv route add default via "$NODE_SRV6" dev eth0
ip -n node route add "${PREFIX}/96" via "$SRV_LINK6" dev srv0
# Small MTU toward the server: forces PMTUD from the pod.
ip -n node link set srv0 mtu 1280
ip -n srv link set eth0 mtu 1280
sleep 1

log "IPv6 reachability pod -> server"
ip netns exec pod ping -6 -c 1 -W 2 "$SRV6" >/dev/null || fail "IPv6 baseline broken"

log "servers"
head -c 5000000 /dev/urandom >"$WORK/big"
ip netns exec srv python3 - "$SRV6" "$PORT" "$WORK" >"$WORK/http.log" 2>&1 <<'EOF' &
import http.server, socket, sys
addr, port, root = sys.argv[1], int(sys.argv[2]), sys.argv[3]
class H(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **k):
        super().__init__(*a, directory=root, **k)
    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(n)
        out = str(len(body)).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)
    def log_message(self, *a):
        pass
class S(http.server.ThreadingHTTPServer):
    address_family = socket.AF_INET6
S((addr, port), H).serve_forever()
EOF
HTTP_PID=$!
ip netns exec srv python3 - "$SRV6" >"$WORK/udp.log" 2>&1 <<'EOF' &
import socket, sys
s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
s.bind((sys.argv[1], 9999))
while True:
    d, a = s.recvfrom(65535)
    s.sendto(d, a)
EOF
UDP_PID=$!
for _ in 1 2 3 4 5 6 7 8 9 10; do
	ip netns exec srv ss -Hltn "sport = :$PORT" | grep -q LISTEN && break
	sleep 0.5
done

if [ "$NO_CLAT" -eq 1 ]; then
	log "harness only: IPv6 HTTP from pod"
	ip netns exec pod curl -6 --noproxy '*' -sS -o /dev/null "http://[$SRV6]:$PORT/big" || fail "IPv6 HTTP"
	echo "harness OK"
	exit 0
fi

log "CNI conf"
LXC_MAC="$(ip -n node -o link show lxc0 | sed -n 's/.*link\/ether \([0-9a-f:]*\).*/\1/p')"
POD_MAC="$(ip -n pod -o link show eth0 | sed -n 's/.*link\/ether \([0-9a-f:]*\).*/\1/p')"
cat >"$WORK/conf.json" <<EOF
{
  "cniVersion": "1.0.0",
  "name": "cilium",
  "type": "cilium-clat",
  "clatPrefix": "${PREFIX}/96",
  "podIPv4": "192.0.0.2/29",
  "gatewayIPv4": "192.0.0.1",
  "logFile": "$WORK/cilium-clat.log",
  "prevResult": {
    "cniVersion": "1.0.0",
    "interfaces": [
      {"name": "lxc0", "mac": "$LXC_MAC"},
      {"name": "eth0", "mac": "$POD_MAC", "sandbox": "/run/netns/pod"}
    ],
    "ips": [{"address": "$POD6/128", "interface": 1}],
    "routes": [{"dst": "::/0"}]
  }
}
EOF
cni() {
	# The plugin runs in the node netns, like on a real host, so that the
	# veth peer lookup by index resolves to lxc0.
	ip netns exec node env CNI_COMMAND="$1" CNI_CONTAINERID=test CNI_NETNS=/run/netns/pod \
		CNI_IFNAME=eth0 CNI_PATH="$(dirname "$BIN")" \
		CNI_ARGS="K8S_POD_NAMESPACE=default;K8S_POD_NAME=test" \
		"$BIN" <"$WORK/conf.json"
}
log "ADD with a sidecar-style IPv4 stack already present must pass through"
ip -n pod link add clat type dummy
ip -n pod link set clat up
ip -n pod addr add 192.0.0.1/32 dev clat
ip -n pod route add default dev clat metric 2048 mtu 1260
cni ADD >"$WORK/add-foreign.json" || { cat "$WORK/add-foreign.json"; fail "ADD (foreign)"; }
grep -q "$POD6" "$WORK/add-foreign.json" || fail "ADD (foreign) must pass prevResult through"
if ip -n pod addr show eth0 | grep -q 192.0.0.2; then fail "ADD (foreign) must not add our address"; fi
if ip netns exec pod tc filter show dev eth0 egress 2>/dev/null | grep -q clat; then fail "ADD (foreign) must not attach"; fi
grep -q 'sidecar' "$WORK/cilium-clat.log" || fail "ADD (foreign) must log the skip"
cni CHECK || fail "CHECK after a foreign skip must succeed"
ip -n pod link del clat

log "CNI ADD"
cni ADD >"$WORK/add.json" || { cat "$WORK/add.json"; echo; cat "$WORK/cilium-clat.log"; fail "ADD"; }
grep -q "$POD6" "$WORK/add.json" || fail "ADD result must pass prevResult through"
grep -q '192.0.0.2' "$WORK/add.json" && fail "ADD result must not contain the IPv4 address"

log "pod state"
ip -n pod addr show eth0
ip -n pod route show
ip -n pod neigh show
ip netns exec pod tc filter show dev eth0 egress
ip netns exec pod tc filter show dev eth0 ingress

log "CNI CHECK"
cni CHECK || fail "CHECK"

log "IPv4 ping (echo request/reply translation)"
ip netns exec pod ping -4 -c 3 -W 2 "$SRV4" || fail "ping"

log "IPv4 HTTP (TCP)"
ip netns exec pod curl -4 --noproxy '*' -sS -o /dev/null "http://$SRV4:$PORT/" || fail "small HTTP"

log "IPv4 large download (PMTUD through a 1280-byte link, GSO/GRO)"
ip netns exec pod curl -4 --noproxy '*' -sS -o "$WORK/big.out" "http://$SRV4:$PORT/big" || fail "large HTTP"
cmp "$WORK/big" "$WORK/big.out" || fail "download corrupted"

log "IPv4 large upload (TCP PMTUD pod -> server through the 1280-byte link)"
n="$(ip netns exec pod curl -4 --noproxy '*' -sS --data-binary "@$WORK/big" "http://$SRV4:$PORT/upload")" || fail "upload"
[ "$n" = "5000000" ] || fail "upload: server received $n bytes, want 5000000"

log "ping with DF (Packet Too Big -> Fragmentation Needed, mtu 1260)"
ip netns exec pod ping -4 -M do -s 1400 -c 2 -W 2 "$SRV4" >"$WORK/pingdf.log" 2>&1 || true
cat "$WORK/pingdf.log"
grep -q 'mtu = 1260' "$WORK/pingdf.log" || fail "expected 'mtu = 1260' from a translated Packet Too Big"
ip netns exec pod ping -4 -M do -s 1200 -c 2 -W 2 "$SRV4" >/dev/null || fail "1200-byte DF ping must pass"

log "tracepath (informational: IP_PMTUDISC_PROBE ignores the route MTU)"
ip netns exec pod tracepath -4 -n "$SRV4" || true

log "UDP echo: small, zero-checksum, and fragmented datagrams"
ip netns exec pod python3 - "$SRV4" <<'EOF' || fail "UDP"
import socket, sys, os
dst = (sys.argv[1], 9999)
# The first datagram larger than the path MTU is lost by design: the router's
# Packet Too Big, translated to Fragmentation Needed, teaches the pod's IPv4
# stack a 1260-byte path MTU and the retry goes through. Applications retry.
for size, nocheck in [(10, False), (10, True), (1400, False), (3000, False), (3000, True), (9000, False)]:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(1)
    if nocheck:
        s.setsockopt(socket.SOL_SOCKET, 11, 1)  # SO_NO_CHECK
    data = os.urandom(size)
    back = None
    for attempt in range(1, 5):
        try:
            s.sendto(data, dst)
            back, _ = s.recvfrom(65535)
            break
        except socket.timeout:
            continue
        except OSError as e:
            print(f"size={size} nocheck={nocheck}: send error {e}")
            break
    if back is None:
        if size > 1400 and nocheck:
            print(f"size={size} nocheck={nocheck}: no reply (expected: zero-checksum fragments are dropped)")
            continue
        print(f"size={size} nocheck={nocheck}: TIMEOUT after {attempt} attempts")
        sys.exit(1)
    assert back == data, f"size={size}: payload mismatch"
    print(f"size={size} nocheck={nocheck}: ok (attempt {attempt})")
EOF

log "counters"
"$BIN" counters --netns /run/netns/pod

log "CNI DEL"
cni DEL || fail "DEL"
if ip -n pod addr show eth0 | grep -q 192.0.0.2; then fail "address left behind"; fi
if ip netns exec pod tc filter show dev eth0 egress | grep -q clat; then fail "filter left behind"; fi
cni DEL || fail "second DEL must succeed"

log "log file"
cat "$WORK/cilium-clat.log"
echo
echo "ALL OK"
