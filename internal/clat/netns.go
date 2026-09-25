package clat

import (
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// IPv4 header size: the IPv4 route MTU is the interface MTU minus this.
const ipv4HeaderOverhead = 20

// IPv4Setup describes the IPv4 state installed in the pod netns.
type IPv4Setup struct {
	PodIPv4 netip.Prefix
	Gateway netip.Addr
	PeerMAC net.HardwareAddr
}

func ipNet(p netip.Prefix) *net.IPNet {
	return &net.IPNet{IP: p.Addr().AsSlice(), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())}
}

func hostRoute(a netip.Addr) *net.IPNet {
	return &net.IPNet{IP: a.AsSlice(), Mask: net.CIDRMask(a.BitLen(), a.BitLen())}
}

func (s IPv4Setup) addr(link netlink.Link) *netlink.Addr {
	return &netlink.Addr{
		IPNet:     ipNet(s.PodIPv4),
		Flags:     unix.IFA_F_NOPREFIXROUTE,
		LinkIndex: link.Attrs().Index,
	}
}

func (s IPv4Setup) neigh(link netlink.Link) *netlink.Neigh {
	return &netlink.Neigh{
		LinkIndex:    link.Attrs().Index,
		Family:       unix.AF_INET,
		State:        netlink.NUD_PERMANENT,
		IP:           s.Gateway.AsSlice(),
		HardwareAddr: s.PeerMAC,
	}
}

func (s IPv4Setup) gatewayRoute(link netlink.Link) *netlink.Route {
	return &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       hostRoute(s.Gateway),
		Scope:     netlink.SCOPE_LINK,
		Table:     unix.RT_TABLE_MAIN,
		Protocol:  unix.RTPROT_STATIC,
	}
}

// RouteMTU returns the MTU for the IPv4 default route on a link.
func RouteMTU(linkMTU int) int {
	return linkMTU - ipv4HeaderOverhead
}

func (s IPv4Setup) defaultRoute(link netlink.Link) *netlink.Route {
	return &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
		Gw:        s.Gateway.AsSlice(),
		Scope:     netlink.SCOPE_UNIVERSE,
		Table:     unix.RT_TABLE_MAIN,
		Protocol:  unix.RTPROT_STATIC,
		MTU:       RouteMTU(link.Attrs().MTU),
	}
}

// ConfigureIPv4 installs the address, neighbour entry and routes. It must run
// inside the pod netns. It is idempotent.
func ConfigureIPv4(link netlink.Link, s IPv4Setup) error {
	if err := netlink.AddrReplace(link, s.addr(link)); err != nil {
		return fmt.Errorf("add %s to %s: %w", s.PodIPv4, link.Attrs().Name, err)
	}
	if err := netlink.NeighSet(s.neigh(link)); err != nil {
		return fmt.Errorf("add neighbour %s -> %s: %w", s.Gateway, s.PeerMAC, err)
	}
	if err := netlink.RouteReplace(s.gatewayRoute(link)); err != nil {
		return fmt.Errorf("add route %s/32: %w", s.Gateway, err)
	}
	if err := netlink.RouteReplace(s.defaultRoute(link)); err != nil {
		return fmt.Errorf("add IPv4 default route via %s: %w", s.Gateway, err)
	}
	return nil
}

func ignoreNotFound(err error) error {
	if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ESRCH) || errors.Is(err, unix.EADDRNOTAVAIL) {
		return nil
	}
	return err
}

// RemoveIPv4 undoes ConfigureIPv4. Missing pieces are not an error.
func RemoveIPv4(link netlink.Link, s IPv4Setup) error {
	var errs []error
	if err := ignoreNotFound(netlink.RouteDel(s.defaultRoute(link))); err != nil {
		errs = append(errs, fmt.Errorf("delete default route: %w", err))
	}
	if err := ignoreNotFound(netlink.RouteDel(s.gatewayRoute(link))); err != nil {
		errs = append(errs, fmt.Errorf("delete gateway route: %w", err))
	}
	if err := ignoreNotFound(netlink.NeighDel(s.neigh(link))); err != nil {
		errs = append(errs, fmt.Errorf("delete neighbour: %w", err))
	}
	if err := ignoreNotFound(netlink.AddrDel(link, s.addr(link))); err != nil {
		errs = append(errs, fmt.Errorf("delete address: %w", err))
	}
	return errors.Join(errs...)
}

// CheckIPv4 verifies the state installed by ConfigureIPv4.
func CheckIPv4(link netlink.Link, s IPv4Setup) error {
	addrs, err := netlink.AddrList(link, unix.AF_INET)
	if err != nil {
		return err
	}
	found := false
	for _, a := range addrs {
		if a.IPNet != nil && a.IPNet.String() == ipNet(s.PodIPv4).String() {
			found = true
		}
	}
	if !found {
		return fmt.Errorf("address %s missing on %s", s.PodIPv4, link.Attrs().Name)
	}

	neighs, err := netlink.NeighList(link.Attrs().Index, unix.AF_INET)
	if err != nil {
		return err
	}
	found = false
	for _, n := range neighs {
		if n.IP.Equal(s.Gateway.AsSlice()) {
			if n.State&netlink.NUD_PERMANENT == 0 {
				return fmt.Errorf("neighbour %s is not permanent", s.Gateway)
			}
			if n.HardwareAddr.String() != s.PeerMAC.String() {
				return fmt.Errorf("neighbour %s has MAC %s, want %s", s.Gateway, n.HardwareAddr, s.PeerMAC)
			}
			found = true
		}
	}
	if !found {
		return fmt.Errorf("neighbour entry for %s missing", s.Gateway)
	}

	routes, err := netlink.RouteListFiltered(unix.AF_INET, &netlink.Route{LinkIndex: link.Attrs().Index}, netlink.RT_FILTER_OIF)
	if err != nil {
		return err
	}
	haveGw, haveDefault := false, false
	for _, r := range routes {
		switch {
		case r.Dst != nil && r.Dst.String() == hostRoute(s.Gateway).String():
			haveGw = true
		case r.Dst == nil || r.Dst.IP.Equal(net.IPv4zero):
			if !r.Gw.Equal(s.Gateway.AsSlice()) {
				return fmt.Errorf("IPv4 default route via %s, want %s", r.Gw, s.Gateway)
			}
			if want := RouteMTU(link.Attrs().MTU); r.MTU != want {
				return fmt.Errorf("IPv4 default route MTU %d, want %d", r.MTU, want)
			}
			haveDefault = true
		}
	}
	if !haveGw {
		return fmt.Errorf("route to %s missing", s.Gateway)
	}
	if !haveDefault {
		return fmt.Errorf("IPv4 default route missing")
	}
	return nil
}
