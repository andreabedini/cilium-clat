package clat

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
)

// CounterNames mirrors enum clat_counter in bpf/clat.c.
var CounterNames = []string{
	"egress_translated",
	"ingress_translated",
	"egress_drop_truncated",
	"egress_drop_bad_src",
	"egress_drop_mcast",
	"egress_drop_srcroute",
	"egress_drop_frag_no_csum",
	"egress_drop_icmp_unsupported",
	"egress_drop_too_big",
	"egress_drop_helper",
	"ingress_drop_truncated",
	"ingress_drop_exthdr",
	"ingress_drop_udp_zero_csum",
	"ingress_drop_frag_icmp",
	"ingress_drop_icmp_unsupported",
	"ingress_drop_icmp_inner",
	"ingress_drop_helper",
}

// Counter indexes used by tests.
const (
	CntEgressTranslated  = 0
	CntIngressTranslated = 1
)

// ReadCounters sums the per-CPU counters of the map.
func ReadCounters(m *ebpf.Map) (map[string]uint64, error) {
	out := make(map[string]uint64, len(CounterNames))
	for i, name := range CounterNames {
		var per []uint64
		if err := m.Lookup(uint32(i), &per); err != nil {
			return nil, fmt.Errorf("lookup counter %d: %w", i, err)
		}
		var sum uint64
		for _, v := range per {
			sum += v
		}
		out[name] = sum
	}
	return out, nil
}

// CountersFromLink finds the counters map through the attached egress
// filter. Must run inside the pod netns. The map is not pinned; it is reached
// through the program's map IDs.
func CountersFromLink(link netlink.Link) (*ebpf.Map, error) {
	filters, err := AttachedFilters(link)
	if err != nil {
		return nil, err
	}
	f, ok := filters[EgressProgramName]
	if !ok {
		return nil, fmt.Errorf("%s is not attached to %s", EgressProgramName, link.Attrs().Name)
	}
	prog, err := ebpf.NewProgramFromID(ebpf.ProgramID(f.Id))
	if err != nil {
		return nil, fmt.Errorf("open program id %d: %w", f.Id, err)
	}
	defer prog.Close()
	info, err := prog.Info()
	if err != nil {
		return nil, err
	}
	ids, ok := info.MapIDs()
	if !ok {
		return nil, fmt.Errorf("kernel does not report map IDs")
	}
	for _, id := range ids {
		m, err := ebpf.NewMapFromID(id)
		if err != nil {
			return nil, err
		}
		mi, err := m.Info()
		if err != nil {
			m.Close()
			return nil, err
		}
		if mi.Name == "clat_counters" {
			return m, nil
		}
		m.Close()
	}
	return nil, fmt.Errorf("counters map not found among program maps")
}
