package clat

// Netlink tests. They need CAP_NET_ADMIN in the current network namespace:
// run as root, or unprivileged with `unshare -rn go test -run IPv4State ./internal/clat/`.
// They skip otherwise. Every test creates its own dummy links and removes
// them again.

import (
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func dummyLink(t *testing.T, name string) netlink.Link {
	t.Helper()
	l := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name, MTU: 1500}}
	if err := netlink.LinkAdd(l); err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			t.Skipf("needs CAP_NET_ADMIN: %v", err)
		}
		t.Fatalf("add dummy %s: %v", name, err)
	}
	t.Cleanup(func() { netlink.LinkDel(l) })
	if err := netlink.LinkSetUp(l); err != nil {
		t.Fatal(err)
	}
	link, err := netlink.LinkByName(name)
	if err != nil {
		t.Fatal(err)
	}
	return link
}

func TestIPv4StateOursAndCheck(t *testing.T) {
	eth0 := dummyLink(t, "clattest0")
	setup := IPv4Setup{
		PodIPv4: netip.MustParsePrefix("192.0.0.2/29"),
		Gateway: netip.MustParseAddr("192.0.0.1"),
		PeerMAC: net.HardwareAddr{0x02, 0, 0, 0, 0, 0x01},
	}
	st, err := InspectIPv4(eth0.Attrs().Name, setup)
	if err != nil {
		t.Fatal(err)
	}
	if st != IPv4None {
		t.Fatalf("fresh netns: state %s, want none", st)
	}

	if err := ConfigureIPv4(eth0, setup); err != nil {
		t.Fatal(err)
	}
	if err := ConfigureIPv4(eth0, setup); err != nil {
		t.Fatalf("second configure must be idempotent: %v", err)
	}
	if st, _ = InspectIPv4(eth0.Attrs().Name, setup); st != IPv4Ours {
		t.Fatalf("after configure: state %s, want ours", st)
	}
	if err := CheckIPv4(eth0, setup); err != nil {
		t.Fatalf("check: %v", err)
	}

	if err := RemoveIPv4(eth0, setup); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if err := RemoveIPv4(eth0, setup); err != nil {
		t.Fatalf("second remove must be idempotent: %v", err)
	}
	if st, _ = InspectIPv4(eth0.Attrs().Name, setup); st != IPv4None {
		t.Fatalf("after remove: state %s, want none", st)
	}
	if err := CheckIPv4(eth0, setup); err == nil {
		t.Fatal("check must fail after remove")
	}
}

// A CLAT sidecar's layout: a tun-like device with 192.0.0.1/32 and an IPv4
// default route with a high metric. The plugin must see it as foreign.
func TestIPv4StateForeignSidecar(t *testing.T) {
	eth0 := dummyLink(t, "clattest0")
	clat := dummyLink(t, "clattest1")
	setup := IPv4Setup{
		PodIPv4: netip.MustParsePrefix("192.0.0.2/29"),
		Gateway: netip.MustParseAddr("192.0.0.1"),
	}
	addr, _ := netlink.ParseAddr("192.0.0.1/32")
	if err := netlink.AddrAdd(clat, addr); err != nil {
		t.Fatal(err)
	}
	if st, _ := InspectIPv4(eth0.Attrs().Name, setup); st != IPv4Foreign {
		t.Fatalf("sidecar address: state %s, want foreign", st)
	}
	if err := netlink.RouteAdd(&netlink.Route{
		LinkIndex: clat.Attrs().Index,
		Dst:       &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
		Priority:  2048,
		MTU:       1260,
	}); err != nil {
		t.Fatal(err)
	}
	if st, _ := InspectIPv4(eth0.Attrs().Name, setup); st != IPv4Foreign {
		t.Fatalf("sidecar route: state %s, want foreign", st)
	}
	// Deleting the address also drops the route that used it as source.
	if err := netlink.AddrDel(clat, addr); err != nil {
		t.Fatal(err)
	}
	if st, _ := InspectIPv4(eth0.Attrs().Name, setup); st != IPv4None {
		t.Fatalf("after sidecar teardown: state %s, want none", st)
	}
	// A default route alone, with no address anywhere: still foreign.
	if err := netlink.RouteAdd(&netlink.Route{
		LinkIndex: clat.Attrs().Index,
		Dst:       &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
		Priority:  2048,
	}); err != nil {
		t.Fatal(err)
	}
	if st, _ := InspectIPv4(eth0.Attrs().Name, setup); st != IPv4Foreign {
		t.Fatalf("route only: state %s, want foreign", st)
	}
}
