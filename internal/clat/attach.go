package clat

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	EgressProgramName  = "clat_egress"
	IngressProgramName = "clat_ingress"
	filterPriority     = 1
)

// Constants are the per-pod values written into the program's .rodata.
type Constants struct {
	Prefix  netip.Prefix // /96
	PodIPv6 netip.Addr
	PodIPv4 netip.Addr
	// ErrSrcIPv4 is the source of ICMPv4 errors translated from ICMPv6
	// errors sent by routers outside the CLAT prefix (RFC 7335: 192.0.0.8).
	ErrSrcIPv4 netip.Addr
}

// Spec returns the collection spec with the per-pod constants applied.
func (c Constants) Spec() (*ebpf.CollectionSpec, error) {
	spec, err := loadClat()
	if err != nil {
		return nil, fmt.Errorf("load embedded BPF object: %w", err)
	}
	if !c.Prefix.Addr().Is6() || c.Prefix.Bits() != 96 {
		return nil, fmt.Errorf("prefix %s is not an IPv6 /96", c.Prefix)
	}
	if !c.PodIPv6.Is6() || c.PodIPv6.Is4In6() {
		return nil, fmt.Errorf("pod address %s is not IPv6", c.PodIPv6)
	}
	if !c.PodIPv4.Is4() {
		return nil, fmt.Errorf("pod IPv4 address %s is not IPv4", c.PodIPv4)
	}
	errSrc := c.ErrSrcIPv4
	if !errSrc.IsValid() {
		errSrc = netip.MustParseAddr(DefaultErrorSourceIPv4)
	}
	if !errSrc.Is4() {
		return nil, fmt.Errorf("ICMP error source %s is not IPv4", errSrc)
	}
	prefix := c.Prefix.Masked().Addr().As16()
	pod6 := c.PodIPv6.As16()
	pod4 := c.PodIPv4.As4()
	err4 := errSrc.As4()
	for name, v := range map[string]any{
		"CLAT_PREFIX": prefix,
		"POD_IP6":     pod6,
		"POD_IP4":     pod4,
		"ERR_IP4":     err4,
	} {
		vs, ok := spec.Variables[name]
		if !ok {
			return nil, fmt.Errorf("BPF object has no variable %s", name)
		}
		if err := vs.Set(v); err != nil {
			return nil, fmt.Errorf("set %s: %w", name, err)
		}
	}
	return spec, nil
}

// Programs holds the loaded programs and the counters map.
type Programs struct {
	objs clatObjects
}

// Load loads both programs into the kernel with the given constants.
func Load(c Constants) (*Programs, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock limit: %w", err)
	}
	spec, err := c.Spec()
	if err != nil {
		return nil, err
	}
	p := &Programs{}
	if err := spec.LoadAndAssign(&p.objs, nil); err != nil {
		// A wrapped *ebpf.VerifierError prints the full log with %+v.
		return nil, fmt.Errorf("load BPF programs: %w", err)
	}
	return p, nil
}

func (p *Programs) Close() error           { return p.objs.Close() }
func (p *Programs) Egress() *ebpf.Program  { return p.objs.ClatEgress }
func (p *Programs) Ingress() *ebpf.Program { return p.objs.ClatIngress }
func (p *Programs) Counters() *ebpf.Map    { return p.objs.ClatCounters }

// Tags returns the kernel tags of the egress and ingress programs.
func (p *Programs) Tags() (egress, ingress string, err error) {
	ei, err := p.objs.ClatEgress.Info()
	if err != nil {
		return "", "", err
	}
	ii, err := p.objs.ClatIngress.Info()
	if err != nil {
		return "", "", err
	}
	return ei.Tag, ii.Tag, nil
}

func clsactQdisc(link netlink.Link) *netlink.GenericQdisc {
	return &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
}

func bpfFilter(link netlink.Link, parent uint32, prog *ebpf.Program, name string) *netlink.BpfFilter {
	return &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    parent,
			Handle:    netlink.MakeHandle(0, 1),
			Protocol:  unix.ETH_P_ALL,
			Priority:  filterPriority,
		},
		Fd:           prog.FD(),
		Name:         name,
		DirectAction: true,
	}
}

// Attach adds a clsact qdisc on the link and attaches the programs as
// direct-action cls_bpf filters. The kernel keeps the programs alive after
// the plugin exits, and removes them with the link. Must run inside the pod
// netns.
func Attach(link netlink.Link, p *Programs) error {
	if err := netlink.QdiscAdd(clsactQdisc(link)); err != nil && !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("add clsact qdisc on %s: %w", link.Attrs().Name, err)
	}
	if err := netlink.FilterReplace(bpfFilter(link, netlink.HANDLE_MIN_EGRESS, p.Egress(), EgressProgramName)); err != nil {
		return fmt.Errorf("attach %s: %w", EgressProgramName, err)
	}
	if err := netlink.FilterReplace(bpfFilter(link, netlink.HANDLE_MIN_INGRESS, p.Ingress(), IngressProgramName)); err != nil {
		return fmt.Errorf("attach %s: %w", IngressProgramName, err)
	}
	return nil
}

// Detach removes the filters and the qdisc. Missing pieces are not an error.
func Detach(link netlink.Link) error {
	var errs []error
	for _, parent := range []uint32{netlink.HANDLE_MIN_EGRESS, netlink.HANDLE_MIN_INGRESS} {
		filters, err := netlink.FilterList(link, parent)
		if err != nil {
			if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOENT) {
				continue // no clsact qdisc
			}
			errs = append(errs, err)
			continue
		}
		for _, f := range filters {
			bf, ok := f.(*netlink.BpfFilter)
			if !ok || (bf.Name != EgressProgramName && bf.Name != IngressProgramName) {
				continue
			}
			if err := netlink.FilterDel(f); err != nil && !errors.Is(err, unix.ENOENT) {
				errs = append(errs, fmt.Errorf("delete filter %s: %w", bf.Name, err))
			}
		}
	}
	if err := netlink.QdiscDel(clsactQdisc(link)); err != nil && !errors.Is(err, unix.ENOENT) && !errors.Is(err, unix.EINVAL) {
		errs = append(errs, fmt.Errorf("delete clsact qdisc: %w", err))
	}
	return errors.Join(errs...)
}

// AttachedFilters returns the attached CLAT filters keyed by program name.
func AttachedFilters(link netlink.Link) (map[string]*netlink.BpfFilter, error) {
	out := map[string]*netlink.BpfFilter{}
	for name, parent := range map[string]uint32{
		EgressProgramName:  netlink.HANDLE_MIN_EGRESS,
		IngressProgramName: netlink.HANDLE_MIN_INGRESS,
	} {
		filters, err := netlink.FilterList(link, parent)
		if err != nil {
			return nil, fmt.Errorf("list filters: %w", err)
		}
		for _, f := range filters {
			if bf, ok := f.(*netlink.BpfFilter); ok && bf.Name == name && bf.DirectAction {
				out[name] = bf
			}
		}
	}
	return out, nil
}

// CheckAttached verifies both filters are present and carry the expected
// program tags.
func CheckAttached(link netlink.Link, egressTag, ingressTag string) error {
	filters, err := AttachedFilters(link)
	if err != nil {
		return err
	}
	for name, want := range map[string]string{EgressProgramName: egressTag, IngressProgramName: ingressTag} {
		f, ok := filters[name]
		if !ok {
			return fmt.Errorf("filter %s missing on %s", name, link.Attrs().Name)
		}
		if f.Tag != want {
			return fmt.Errorf("filter %s has program tag %s, want %s", name, f.Tag, want)
		}
	}
	return nil
}
