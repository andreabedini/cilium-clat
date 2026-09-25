// cilium-clat is a chained CNI plugin that installs a stateless eBPF CLAT on
// the pod interface created by cilium-cni.
//
// Invoked by the container runtime it speaks CNI on stdin/stdout. It also has
// one debugging subcommand:
//
//	cilium-clat counters --netns /proc/<pid>/ns/net [--ifname eth0]
package main

import (
	"flag"
	"fmt"
	"os"
	"sort"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/ns"
	bv "github.com/containernetworking/plugins/pkg/utils/buildversion"
	"github.com/vishvananda/netlink"

	"github.com/andreabedini/cilium-clat/internal/clat"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "counters" {
		os.Exit(counters(os.Args[2:]))
	}
	skel.PluginMainFuncs(skel.CNIFuncs{
		Add:    clat.CmdAdd,
		Del:    clat.CmdDel,
		Check:  clat.CmdCheck,
		GC:     func(*skel.CmdArgs) error { return nil },
		Status: func(*skel.CmdArgs) error { return nil },
	}, version.PluginSupports("0.3.0", "0.3.1", "0.4.0", "1.0.0", "1.1.0"), bv.BuildString("cilium-clat"))
}

func counters(argv []string) int {
	fs := flag.NewFlagSet("counters", flag.ContinueOnError)
	netns := fs.String("netns", "", "path to the pod network namespace")
	ifname := fs.String("ifname", "eth0", "pod interface name")
	if err := fs.Parse(argv); err != nil {
		return 2
	}
	if *netns == "" {
		fmt.Fprintln(os.Stderr, "--netns is required")
		return 2
	}
	var out map[string]uint64
	err := ns.WithNetNSPath(*netns, func(ns.NetNS) error {
		link, err := netlink.LinkByName(*ifname)
		if err != nil {
			return err
		}
		m, err := clat.CountersFromLink(link)
		if err != nil {
			return err
		}
		defer m.Close()
		out, err = clat.ReadCounters(m)
		return err
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	names := make([]string, 0, len(out))
	for n := range out {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Printf("%-32s %d\n", n, out[n])
	}
	return 0
}
