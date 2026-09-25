// cilium-clat is a chained CNI plugin that installs a stateless eBPF CLAT on
// the pod interface created by cilium-cni.
//
// Invoked by the container runtime it speaks CNI on stdin/stdout. It also has
// three subcommands:
//
//	cilium-clat install [--dir /host/opt/cni/bin]   copy itself into a CNI bin dir, atomically
//	cilium-clat sleep                                block until SIGTERM (DaemonSet main container)
//	cilium-clat counters --netns /proc/<pid>/ns/net [--ifname eth0]
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"syscall"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/ns"
	bv "github.com/containernetworking/plugins/pkg/utils/buildversion"
	"github.com/vishvananda/netlink"

	"github.com/andreabedini/cilium-clat/internal/clat"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "counters":
			os.Exit(counters(os.Args[2:]))
		case "install":
			os.Exit(install(os.Args[2:]))
		case "sleep":
			os.Exit(sleepForever())
		}
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

// install copies the running binary into a CNI plugin directory. It writes
// to a temporary name and renames, so the runtime never executes a partial
// binary. This is what the installer DaemonSet's init container runs.
func install(argv []string) int {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	dir := fs.String("dir", "/host/opt/cni/bin", "CNI plugin directory (host path as mounted)")
	name := fs.String("name", "cilium-clat", "installed file name")
	if err := fs.Parse(argv); err != nil {
		return 2
	}
	self, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	if err := os.MkdirAll(*dir, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	src, err := os.Open(self)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	defer src.Close()
	tmp := filepath.Join(*dir, "."+*name+".tmp")
	dst, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	if _, err := io.Copy(dst, src); err != nil {
		dst.Close()
		os.Remove(tmp)
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	if err := dst.Sync(); err != nil {
		dst.Close()
		os.Remove(tmp)
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	if err := dst.Close(); err != nil {
		os.Remove(tmp)
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	final := filepath.Join(*dir, *name)
	if err := os.Rename(tmp, final); err != nil {
		os.Remove(tmp)
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	fmt.Printf("installed %s\n", final)
	return 0
}

// sleepForever keeps the DaemonSet pod alive and exits cleanly on SIGTERM.
func sleepForever() int {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	<-sig
	return 0
}
