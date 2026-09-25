package clat

import (
	"net"
	"net/netip"
	"testing"

	current "github.com/containernetworking/cni/pkg/types/100"
)

const baseConf = `{
  "cniVersion": "1.0.0",
  "name": "cilium",
  "type": "cilium-clat",
  "clatPrefix": "64:ff9b:1::/96",
  "excludeNamespaces": ["kube-system"],
  "prevResult": {
    "cniVersion": "1.0.0",
    "interfaces": [
      {"name": "lxc1234", "mac": "02:00:00:00:00:01"},
      {"name": "eth0", "mac": "02:00:00:00:00:02", "sandbox": "/proc/1/ns/net"}
    ],
    "ips": [{"address": "2001:db8::2/128", "interface": 1}],
    "routes": [{"dst": "::/0"}]
  }
}`

func TestParseConfigDefaults(t *testing.T) {
	conf, cfg, err := ParseConfig([]byte(baseConf))
	if err != nil {
		t.Fatal(err)
	}
	if conf.PrevResult == nil {
		t.Fatal("prevResult not parsed")
	}
	if cfg.Prefix != netip.MustParsePrefix("64:ff9b:1::/96") {
		t.Errorf("prefix = %s", cfg.Prefix)
	}
	if cfg.PodIPv4 != netip.MustParsePrefix(DefaultPodIPv4) {
		t.Errorf("podIPv4 = %s", cfg.PodIPv4)
	}
	if cfg.Gateway != netip.MustParseAddr(DefaultGatewayIPv4) {
		t.Errorf("gateway = %s", cfg.Gateway)
	}
	if _, ok := cfg.ExcludeNamespaces["kube-system"]; !ok {
		t.Errorf("excludeNamespaces = %v", cfg.ExcludeNamespaces)
	}
	if cfg.FailOpen {
		t.Error("failOpen must default to false")
	}
}

func TestParseConfigRejects(t *testing.T) {
	cases := map[string]string{
		"missing prefix": `{"cniVersion":"1.0.0","name":"x","type":"cilium-clat"}`,
		"not a /96":      `{"cniVersion":"1.0.0","name":"x","type":"cilium-clat","clatPrefix":"64:ff9b:1::/64"}`,
		"host bits set":  `{"cniVersion":"1.0.0","name":"x","type":"cilium-clat","clatPrefix":"64:ff9b:1::1/96"}`,
		"ipv4 prefix":    `{"cniVersion":"1.0.0","name":"x","type":"cilium-clat","clatPrefix":"10.0.0.0/96"}`,
		"bad pod ipv4":   `{"cniVersion":"1.0.0","name":"x","type":"cilium-clat","clatPrefix":"64:ff9b:1::/96","podIPv4":"2001:db8::1/64"}`,
		"gateway == pod": `{"cniVersion":"1.0.0","name":"x","type":"cilium-clat","clatPrefix":"64:ff9b:1::/96","podIPv4":"192.0.0.2/29","gatewayIPv4":"192.0.0.2"}`,
		"bad gateway":    `{"cniVersion":"1.0.0","name":"x","type":"cilium-clat","clatPrefix":"64:ff9b:1::/96","gatewayIPv4":"fe80::1"}`,
		"malformed json": `{`,
	}
	for name, in := range cases {
		if _, _, err := ParseConfig([]byte(in)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestPodNamespace(t *testing.T) {
	if got := PodNamespace("IgnoreUnknown=1;K8S_POD_NAMESPACE=media;K8S_POD_NAME=x"); got != "media" {
		t.Errorf("got %q", got)
	}
	if got := PodNamespace(""); got != "" {
		t.Errorf("got %q", got)
	}
}

func result(ips ...string) *current.Result {
	r := &current.Result{CNIVersion: "1.0.0"}
	for _, s := range ips {
		p := netip.MustParsePrefix(s)
		r.IPs = append(r.IPs, &current.IPConfig{Address: net.IPNet{
			IP:   p.Addr().AsSlice(),
			Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen()),
		}})
	}
	return r
}

func TestDecide(t *testing.T) {
	_, cfg, err := ParseConfig([]byte(baseConf))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		res  *current.Result
		ns   string
		want SkipReason
		pod6 string
	}{
		{"ipv6 only", result("2001:db8::2/128"), "default", SkipNone, "2001:db8::2"},
		{"dual stack", result("2001:db8::2/128", "10.0.0.5/32"), "default", SkipHasIPv4, ""},
		{"ipv4 only", result("10.0.0.5/32"), "default", SkipHasIPv4, ""},
		{"no ips", result(), "default", SkipNoIPv6, ""},
		{"excluded", result("2001:db8::2/128"), "kube-system", SkipExcludedNS, ""},
		{"nil result", nil, "default", SkipNoPrevResult, ""},
	}
	for _, c := range cases {
		pod6, skip := Decide(cfg, c.res, c.ns)
		if skip != c.want {
			t.Errorf("%s: skip = %q, want %q", c.name, skip, c.want)
		}
		if c.pod6 != "" && pod6 != netip.MustParseAddr(c.pod6) {
			t.Errorf("%s: pod6 = %s, want %s", c.name, pod6, c.pod6)
		}
	}
}

func TestDecideIncludeNamespaces(t *testing.T) {
	_, cfg, err := ParseConfig([]byte(`{"cniVersion":"1.0.0","name":"x","type":"cilium-clat",
		"clatPrefix":"64:ff9b:1::/96","includeNamespaces":["openclaw"],"excludeNamespaces":["kube-system","openclaw"]}`))
	if err != nil {
		t.Fatal(err)
	}
	// exclude wins over include; anything not included is skipped.
	for ns, want := range map[string]SkipReason{
		"openclaw":    SkipExcludedNS,
		"default":     SkipNotIncluded,
		"kube-system": SkipExcludedNS,
	} {
		if _, skip := Decide(cfg, result("2001:db8::2/128"), ns); skip != want {
			t.Errorf("%s: skip = %q, want %q", ns, skip, want)
		}
	}
	_, cfg, err = ParseConfig([]byte(`{"cniVersion":"1.0.0","name":"x","type":"cilium-clat",
		"clatPrefix":"64:ff9b:1::/96","includeNamespaces":["openclaw"],"failOpen":true}`))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.FailOpen {
		t.Error("failOpen not parsed")
	}
	if _, skip := Decide(cfg, result("2001:db8::2/128"), "openclaw"); skip != SkipNone {
		t.Errorf("openclaw: skip = %q", skip)
	}
	if _, skip := Decide(cfg, result("2001:db8::2/128"), "media"); skip != SkipNotIncluded {
		t.Errorf("media: skip = %q", skip)
	}
}

func TestHostInterfaceMAC(t *testing.T) {
	conf, _, err := ParseConfig([]byte(baseConf))
	if err != nil {
		t.Fatal(err)
	}
	res, err := current.NewResultFromResult(conf.PrevResult)
	if err != nil {
		t.Fatal(err)
	}
	if got := HostInterfaceMAC(res, "eth0"); got != "02:00:00:00:00:01" {
		t.Errorf("got %q", got)
	}
}

func TestRouteMTU(t *testing.T) {
	if got := RouteMTU(1500); got != 1480 {
		t.Errorf("got %d", got)
	}
}

func TestSpecConstants(t *testing.T) {
	c := Constants{
		Prefix:  netip.MustParsePrefix("64:ff9b:1::/96"),
		PodIPv6: netip.MustParseAddr("2001:db8::2"),
		PodIPv4: netip.MustParseAddr("192.0.0.2"),
	}
	spec, err := c.Spec()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"CLAT_PREFIX", "POD_IP6", "POD_IP4"} {
		v, ok := spec.Variables[name]
		if !ok {
			t.Fatalf("variable %s missing", name)
		}
		if !v.Constant() {
			t.Errorf("variable %s is not constant (.rodata)", name)
		}
	}
	if _, ok := spec.Programs[EgressProgramName]; !ok {
		t.Errorf("program %s missing", EgressProgramName)
	}
	if _, ok := spec.Programs[IngressProgramName]; !ok {
		t.Errorf("program %s missing", IngressProgramName)
	}
	if len(CounterNames) != int(spec.Maps["clat_counters"].MaxEntries) {
		t.Errorf("CounterNames has %d entries, map has %d", len(CounterNames), spec.Maps["clat_counters"].MaxEntries)
	}
}
