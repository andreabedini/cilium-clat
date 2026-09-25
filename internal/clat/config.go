// Package clat implements the cilium-clat chained CNI plugin: a stateless
// eBPF CLAT attached to the pod side of the veth pair that cilium-cni set up.
package clat

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"

	"github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/cni/pkg/version"
)

const (
	DefaultPodIPv4     = "192.0.0.2/29"
	DefaultGatewayIPv4 = "192.0.0.1"
	// RFC 7335 IPv4 dummy address, used as the source of translated ICMP
	// errors that come from routers outside the CLAT prefix.
	DefaultErrorSourceIPv4 = "192.0.0.8"
)

// NetConf is the plugin's entry in the conflist.
type NetConf struct {
	types.PluginConf

	ClatPrefix        string   `json:"clatPrefix"`
	PodIPv4           string   `json:"podIPv4,omitempty"`
	GatewayIPv4       string   `json:"gatewayIPv4,omitempty"`
	ErrorSourceIPv4   string   `json:"errorSourceIPv4,omitempty"`
	ExcludeNamespaces []string `json:"excludeNamespaces,omitempty"`
	LogFile           string   `json:"logFile,omitempty"`
	// FailOpen makes ADD succeed without a CLAT when the CLAT setup fails.
	// The default is fail-closed: the pod does not start.
	FailOpen bool `json:"failOpen,omitempty"`
}

// Config is the validated plugin configuration.
type Config struct {
	Prefix            netip.Prefix // CLAT prefix P, always /96
	PodIPv4           netip.Prefix // address and mask for the pod interface
	Gateway           netip.Addr
	ErrorSource       netip.Addr // source of translated router ICMP errors
	ExcludeNamespaces map[string]struct{}
	LogFile           string
	FailOpen          bool
}

// ParseConfig parses and validates the plugin's stdin.
func ParseConfig(stdin []byte) (*NetConf, *Config, error) {
	conf := &NetConf{}
	if err := json.Unmarshal(stdin, conf); err != nil {
		return nil, nil, fmt.Errorf("parse network configuration: %w", err)
	}
	if err := version.ParsePrevResult(&conf.PluginConf); err != nil {
		return nil, nil, fmt.Errorf("parse prevResult: %w", err)
	}

	cfg := &Config{
		ExcludeNamespaces: map[string]struct{}{},
		LogFile:           conf.LogFile,
		FailOpen:          conf.FailOpen,
	}

	if conf.ClatPrefix == "" {
		return nil, nil, fmt.Errorf("clatPrefix is required")
	}
	p, err := netip.ParsePrefix(conf.ClatPrefix)
	if err != nil {
		return nil, nil, fmt.Errorf("clatPrefix: %w", err)
	}
	if !p.Addr().Is6() || p.Addr().Is4In6() || p.Bits() != 96 {
		return nil, nil, fmt.Errorf("clatPrefix %q must be an IPv6 /96", conf.ClatPrefix)
	}
	if p.Masked() != p {
		return nil, nil, fmt.Errorf("clatPrefix %q has non-zero bits after the /96", conf.ClatPrefix)
	}
	cfg.Prefix = p

	pod := conf.PodIPv4
	if pod == "" {
		pod = DefaultPodIPv4
	}
	pp, err := netip.ParsePrefix(pod)
	if err != nil {
		return nil, nil, fmt.Errorf("podIPv4: %w", err)
	}
	if !pp.Addr().Is4() {
		return nil, nil, fmt.Errorf("podIPv4 %q must be an IPv4 CIDR", pod)
	}
	cfg.PodIPv4 = pp

	gw := conf.GatewayIPv4
	if gw == "" {
		gw = DefaultGatewayIPv4
	}
	ga, err := netip.ParseAddr(gw)
	if err != nil {
		return nil, nil, fmt.Errorf("gatewayIPv4: %w", err)
	}
	if !ga.Is4() {
		return nil, nil, fmt.Errorf("gatewayIPv4 %q must be an IPv4 address", gw)
	}
	if ga == pp.Addr() {
		return nil, nil, fmt.Errorf("gatewayIPv4 must differ from podIPv4")
	}
	cfg.Gateway = ga

	es := conf.ErrorSourceIPv4
	if es == "" {
		es = DefaultErrorSourceIPv4
	}
	ea, err := netip.ParseAddr(es)
	if err != nil {
		return nil, nil, fmt.Errorf("errorSourceIPv4: %w", err)
	}
	if !ea.Is4() {
		return nil, nil, fmt.Errorf("errorSourceIPv4 %q must be an IPv4 address", es)
	}
	cfg.ErrorSource = ea

	for _, ns := range conf.ExcludeNamespaces {
		cfg.ExcludeNamespaces[ns] = struct{}{}
	}
	return conf, cfg, nil
}

// PodNamespace extracts K8S_POD_NAMESPACE from CNI_ARGS ("K=V;K=V").
func PodNamespace(cniArgs string) string {
	for _, kv := range strings.Split(cniArgs, ";") {
		k, v, ok := strings.Cut(kv, "=")
		if ok && k == "K8S_POD_NAMESPACE" {
			return v
		}
	}
	return ""
}

// SkipReason explains why a pod gets no CLAT. Empty means the pod gets one.
type SkipReason string

const (
	SkipNone         SkipReason = ""
	SkipNoIPv6       SkipReason = "pod has no IPv6 address"
	SkipHasIPv4      SkipReason = "pod already has an IPv4 address"
	SkipExcludedNS   SkipReason = "namespace is excluded"
	SkipNoInterface  SkipReason = "prevResult has no sandbox interface"
	SkipNoPrevResult SkipReason = "no prevResult"
)

// Decide inspects the previous plugin's result and returns the pod's IPv6
// address and whether the CLAT should be installed.
func Decide(cfg *Config, res *current.Result, namespace string) (netip.Addr, SkipReason) {
	if res == nil {
		return netip.Addr{}, SkipNoPrevResult
	}
	if _, excluded := cfg.ExcludeNamespaces[namespace]; excluded {
		return netip.Addr{}, SkipExcludedNS
	}
	var pod6 netip.Addr
	for _, ip := range res.IPs {
		if ip == nil {
			continue
		}
		addr, ok := netip.AddrFromSlice(ip.Address.IP)
		if !ok {
			continue
		}
		addr = addr.Unmap()
		if addr.Is4() {
			return netip.Addr{}, SkipHasIPv4
		}
		if !pod6.IsValid() {
			pod6 = addr
		}
	}
	if !pod6.IsValid() {
		return netip.Addr{}, SkipNoIPv6
	}
	return pod6, SkipNone
}

// HostInterfaceMAC returns the MAC of the host-side interface in the result,
// if the previous plugin reported one. Cilium reports the lxc interface
// first, without a sandbox, and the pod interface second.
func HostInterfaceMAC(res *current.Result, podIfName string) string {
	for _, i := range res.Interfaces {
		if i == nil {
			continue
		}
		if i.Sandbox == "" && i.Name != podIfName && i.Mac != "" {
			return i.Mac
		}
	}
	return ""
}
