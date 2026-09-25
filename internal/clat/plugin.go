package clat

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"
)

// openLog returns a logger writing to the configured file. The plugin never
// writes to stdout except for the CNI result.
func openLog(cfg *Config) (*log.Logger, func()) {
	if cfg == nil || cfg.LogFile == "" {
		return log.New(io.Discard, "", 0), func() {}
	}
	f, err := os.OpenFile(cfg.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return log.New(os.Stderr, "cilium-clat: ", log.LstdFlags), func() {}
	}
	return log.New(f, "cilium-clat: ", log.LstdFlags|log.Lmicroseconds), func() { f.Close() }
}

// podLink is what ADD learns about the pod interface.
type podLink struct {
	MAC       net.HardwareAddr
	MTU       int
	PeerIndex int
}

func inspectPodLink(netns, ifName string) (podLink, error) {
	var pl podLink
	err := ns.WithNetNSPath(netns, func(ns.NetNS) error {
		link, err := netlink.LinkByName(ifName)
		if err != nil {
			return fmt.Errorf("find %s in %s: %w", ifName, netns, err)
		}
		if link.Type() != "veth" {
			return fmt.Errorf("%s is a %s link, only veth is supported", ifName, link.Type())
		}
		pl.MAC = link.Attrs().HardwareAddr
		pl.MTU = link.Attrs().MTU
		pl.PeerIndex = link.Attrs().ParentIndex
		return nil
	})
	return pl, err
}

// peerMAC returns the MAC of the host-side veth peer. The peer index reported
// by the kernel is relative to the peer's netns, which is the host netns for
// a Cilium endpoint. The prevResult's host interface is the fallback.
func peerMAC(pl podLink, res *current.Result, ifName string) (net.HardwareAddr, error) {
	if pl.PeerIndex > 0 {
		peer, err := netlink.LinkByIndex(pl.PeerIndex)
		if err == nil && len(peer.Attrs().HardwareAddr) == 6 {
			return peer.Attrs().HardwareAddr, nil
		}
	}
	if mac := HostInterfaceMAC(res, ifName); mac != "" {
		hw, err := net.ParseMAC(mac)
		if err == nil {
			return hw, nil
		}
	}
	return nil, fmt.Errorf("cannot determine the host-side peer MAC of %s (peer index %d)", ifName, pl.PeerIndex)
}

// CmdAdd implements CNI ADD.
func CmdAdd(args *skel.CmdArgs) error {
	conf, cfg, err := ParseConfig(args.StdinData)
	if err != nil {
		return err
	}
	logger, closeLog := openLog(cfg)
	defer closeLog()

	if conf.PrevResult == nil {
		return fmt.Errorf("cilium-clat must be chained after cilium-cni: no prevResult")
	}
	res, err := current.NewResultFromResult(conf.PrevResult)
	if err != nil {
		return fmt.Errorf("convert prevResult: %w", err)
	}

	namespace := PodNamespace(args.Args)
	pod6, skip := Decide(cfg, res, namespace)
	if skip != SkipNone {
		logger.Printf("ADD %s ns=%s: skip: %s", args.ContainerID, namespace, skip)
		return types.PrintResult(res, conf.CNIVersion)
	}

	// Never add a second IPv4 stack next to one that something else owns
	// (a CLAT sidecar, another chained plugin). A re-ADD after a partial
	// failure finds our own state and proceeds: setup is idempotent.
	setup := IPv4Setup{PodIPv4: cfg.PodIPv4, Gateway: cfg.Gateway}
	var state IPv4State
	err = ns.WithNetNSPath(args.Netns, func(ns.NetNS) error {
		var err error
		state, err = InspectIPv4(args.IfName, setup)
		return err
	})
	if err != nil {
		return failOrOpen(cfg, conf, res, logger, args, namespace, fmt.Errorf("inspect pod netns: %w", err))
	}
	if state == IPv4Foreign {
		logger.Printf("ADD %s ns=%s: skip: %s", args.ContainerID, namespace, SkipForeignIPv4)
		return types.PrintResult(res, conf.CNIVersion)
	}

	if err := install(args, cfg, res, pod6, logger); err != nil {
		return failOrOpen(cfg, conf, res, logger, args, namespace, err)
	}
	logger.Printf("ADD %s ns=%s: CLAT installed, pod %s, prefix %s", args.ContainerID, namespace, pod6, cfg.Prefix)
	return types.PrintResult(res, conf.CNIVersion)
}

// failOrOpen is the fail-open switch. Partial state has already been undone
// by the caller; with failOpen the pod starts without a CLAT and the reason is
// in the log, otherwise ADD fails and the pod does not start.
func failOrOpen(cfg *Config, conf *NetConf, res *current.Result, logger *log.Logger, args *skel.CmdArgs, namespace string, err error) error {
	// %+v expands a verifier log in full; the log file is the place for it.
	logger.Printf("ADD %s ns=%s: CLAT setup failed (fail-open=%v): %+v", args.ContainerID, namespace, cfg.FailOpen, err)
	if cfg.FailOpen {
		return types.PrintResult(res, conf.CNIVersion)
	}
	return fmt.Errorf("cilium-clat: %v", err)
}

func install(args *skel.CmdArgs, cfg *Config, res *current.Result, pod6 netip.Addr, logger *log.Logger) error {
	pl, err := inspectPodLink(args.Netns, args.IfName)
	if err != nil {
		return err
	}
	peer, err := peerMAC(pl, res, args.IfName)
	if err != nil {
		return err
	}

	progs, err := Load(Constants{Prefix: cfg.Prefix, PodIPv6: pod6, PodIPv4: cfg.PodIPv4.Addr(), ErrSrcIPv4: cfg.ErrorSource})
	if err != nil {
		return err
	}
	defer progs.Close() // the tc filters hold their own references

	setup := IPv4Setup{PodIPv4: cfg.PodIPv4, Gateway: cfg.Gateway, PeerMAC: peer}
	return ns.WithNetNSPath(args.Netns, func(ns.NetNS) error {
		link, err := netlink.LinkByName(args.IfName)
		if err != nil {
			return fmt.Errorf("find %s: %w", args.IfName, err)
		}
		if err := ConfigureIPv4(link, setup); err != nil {
			_ = RemoveIPv4(link, setup)
			return err
		}
		if err := Attach(link, progs); err != nil {
			_ = Detach(link)
			_ = RemoveIPv4(link, setup)
			return err
		}
		logger.Printf("ADD %s: %s mtu=%d peer=%s route-mtu=%d", args.ContainerID, args.IfName, pl.MTU, peer, RouteMTU(pl.MTU))
		return nil
	})
}

// CmdDel implements CNI DEL. It never fails on missing state.
func CmdDel(args *skel.CmdArgs) error {
	conf, cfg, err := ParseConfig(args.StdinData)
	if err != nil {
		return err
	}
	logger, closeLog := openLog(cfg)
	defer closeLog()
	_ = conf

	if args.Netns == "" {
		return nil
	}
	setup := IPv4Setup{PodIPv4: cfg.PodIPv4, Gateway: cfg.Gateway}
	err = ns.WithNetNSPath(args.Netns, func(ns.NetNS) error {
		link, err := netlink.LinkByName(args.IfName)
		if err != nil {
			var lnf netlink.LinkNotFoundError
			if errors.As(err, &lnf) {
				return nil
			}
			return err
		}
		// The neighbour entry is keyed by IP; the MAC is not needed to delete it.
		return errors.Join(Detach(link), RemoveIPv4(link, setup))
	})
	if err != nil {
		var nsErr ns.NSPathNotExistErr
		if errors.As(err, &nsErr) || errors.Is(err, os.ErrNotExist) {
			logger.Printf("DEL %s: netns %s already gone", args.ContainerID, args.Netns)
			return nil
		}
		// DEL must be idempotent; log and report success. The veth and
		// everything attached to it go away with the netns anyway.
		logger.Printf("DEL %s: cleanup error ignored: %v", args.ContainerID, err)
		return nil
	}
	logger.Printf("DEL %s: cleaned up", args.ContainerID)
	return nil
}

// CmdCheck implements CNI CHECK.
func CmdCheck(args *skel.CmdArgs) error {
	conf, cfg, err := ParseConfig(args.StdinData)
	if err != nil {
		return err
	}
	if conf.PrevResult == nil {
		return fmt.Errorf("cilium-clat must be chained after cilium-cni: no prevResult")
	}
	res, err := current.NewResultFromResult(conf.PrevResult)
	if err != nil {
		return fmt.Errorf("convert prevResult: %w", err)
	}
	pod6, skip := Decide(cfg, res, PodNamespace(args.Args))
	if skip != SkipNone {
		return nil
	}

	// Mirror ADD's decisions: a pod skipped for foreign IPv4 state, or
	// started without a CLAT under failOpen, is not a CHECK failure.
	setup := IPv4Setup{PodIPv4: cfg.PodIPv4, Gateway: cfg.Gateway}
	var state IPv4State
	var filters map[string]*netlink.BpfFilter
	err = ns.WithNetNSPath(args.Netns, func(ns.NetNS) error {
		var err error
		if state, err = InspectIPv4(args.IfName, setup); err != nil {
			return err
		}
		link, err := netlink.LinkByName(args.IfName)
		if err != nil {
			return err
		}
		filters, err = AttachedFilters(link)
		return err
	})
	if err != nil {
		return err
	}
	if state == IPv4Foreign {
		return nil
	}
	if state == IPv4None && len(filters) == 0 {
		if cfg.FailOpen {
			return nil
		}
		return fmt.Errorf("no CLAT state in %s: IPv4 address, routes and filters are all missing", args.Netns)
	}

	pl, err := inspectPodLink(args.Netns, args.IfName)
	if err != nil {
		return err
	}
	peer, err := peerMAC(pl, res, args.IfName)
	if err != nil {
		return err
	}
	progs, err := Load(Constants{Prefix: cfg.Prefix, PodIPv6: pod6, PodIPv4: cfg.PodIPv4.Addr(), ErrSrcIPv4: cfg.ErrorSource})
	if err != nil {
		return err
	}
	defer progs.Close()
	egressTag, ingressTag, err := progs.Tags()
	if err != nil {
		return err
	}

	setup.PeerMAC = peer
	return ns.WithNetNSPath(args.Netns, func(ns.NetNS) error {
		link, err := netlink.LinkByName(args.IfName)
		if err != nil {
			return err
		}
		if err := CheckIPv4(link, setup); err != nil {
			return err
		}
		return CheckAttached(link, egressTag, ingressTag)
	})
}
