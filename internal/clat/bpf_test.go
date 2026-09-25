package clat

// BPF_PROG_TEST_RUN tests. They need CAP_BPF and CAP_NET_ADMIN (run as root)
// and are skipped otherwise. When they run, the kernel verifier's verdict on
// the programs is part of the test.

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"os"
	"testing"
)

func loadTestPrograms(t *testing.T) *Programs {
	t.Helper()
	// A verifier rejection also surfaces as EACCES, so privileges are
	// decided up front: root runs the verifier and must pass it.
	if os.Geteuid() != 0 {
		t.Skip("loading BPF programs needs root (CAP_BPF, CAP_NET_ADMIN)")
	}
	p, err := Load(Constants{Prefix: testPrefix, PodIPv6: testPod6, PodIPv4: testPod4, ErrSrcIPv4: testErr4})
	if err != nil {
		t.Fatalf("load programs: %+v", err)
	}
	t.Cleanup(func() { p.Close() })
	return p
}

func runEgress(t *testing.T, p *Programs, in []byte) (uint32, []byte) {
	t.Helper()
	ret, out, err := p.Egress().Test(in)
	if err != nil {
		t.Fatalf("run clat_egress: %v", err)
	}
	return ret, out
}

func runIngress(t *testing.T, p *Programs, in []byte) (uint32, []byte) {
	t.Helper()
	ret, out, err := p.Ingress().Test(in)
	if err != nil {
		t.Fatalf("run clat_ingress: %v", err)
	}
	return ret, out
}

func expectOK(t *testing.T, ret uint32) {
	t.Helper()
	if ret != tcActOK {
		t.Fatalf("return value %d, want TC_ACT_OK", ret)
	}
}

func expectShot(t *testing.T, ret uint32) {
	t.Helper()
	if ret != tcActShot {
		t.Fatalf("return value %d, want TC_ACT_SHOT", ret)
	}
}

// expectFrame compares two frames but ignores the transport checksum field,
// which verifyL4 checks arithmetically instead.
func expectFrame(t *testing.T, got, want []byte) {
	t.Helper()
	if !bytes.Equal(got, want) {
		t.Errorf("frame mismatch\n got: %x\nwant: %x", got, want)
	}
}

func zeroCsum(t *testing.T, frame []byte) []byte {
	t.Helper()
	p := parse(t, frame)
	off := csumOffset(p.proto)
	if off >= 0 && !(p.frag && p.fragOff != 0) {
		frame = append([]byte(nil), frame...)
		frame[p.hdrLen+off], frame[p.hdrLen+off+1] = 0, 0
	}
	return frame
}

func TestEgressTCP(t *testing.T) {
	p := loadTestPrograms(t)
	seg := tcp(40000, 80, 0x02, []byte("hello"))
	in := packet4(testPod4, testDst4, protoTCP, seg, ip4opts{tos: 0x28, ttl: 64, id: 0x1234, flags: 0x4000})

	ret, out := runEgress(t, p, in)
	expectOK(t, ret)

	got := parse(t, out)
	if got.etherType != etherIP6 || got.version != 6 {
		t.Fatalf("not an IPv6 frame: %+v", got)
	}
	if got.src != testPod6 || got.dst != mapped(testDst4) {
		t.Errorf("addresses %s -> %s", got.src, got.dst)
	}
	if got.tc != 0x28 || got.hop != 64 || got.proto != protoTCP || got.frag {
		t.Errorf("header fields: tc=%#x hop=%d proto=%d frag=%v", got.tc, got.hop, got.proto, got.frag)
	}
	verifyL4(t, got)

	want := packet6(testPod6, mapped(testDst4), 0x28, 64, protoTCP, seg)
	// MAC addresses are untouched by the program.
	copy(want[0:6], macPeer)
	copy(want[6:12], macPod)
	expectFrame(t, out, want)

	c, err := ReadCounters(p.Counters())
	if err != nil {
		t.Fatal(err)
	}
	if c["egress_translated"] != 1 {
		t.Errorf("egress_translated = %d", c["egress_translated"])
	}
}

func TestEgressUDP(t *testing.T) {
	p := loadTestPrograms(t)
	dg := udp(5353, 53, []byte("dns query"))
	in := packet4(testPod4, testDst4, protoUDP, dg, ip4opts{ttl: 61, id: 7})
	ret, out := runEgress(t, p, in)
	expectOK(t, ret)
	got := parse(t, out)
	if got.proto != protoUDP || got.dst != mapped(testDst4) {
		t.Fatalf("bad translation: %+v", got)
	}
	verifyL4(t, got)
	want := packet6(testPod6, mapped(testDst4), 0, 61, protoUDP, dg)
	copy(want[0:12], out[0:12])
	expectFrame(t, out, want)
}

func TestEgressUDPZeroChecksum(t *testing.T) {
	p := loadTestPrograms(t)
	for _, size := range []int{0, 3, 300, 1400} {
		payload := bytes.Repeat([]byte{0xa5, 0x5a, 0x01}, size/3+1)[:size]
		dg := udp(1234, 4321, payload) // checksum field left at zero
		in := frame4(testPod4, testDst4, protoUDP, dg, ip4opts{ttl: 64})
		ret, out := runEgress(t, p, in)
		expectOK(t, ret)
		got := parse(t, out)
		if got.proto != protoUDP {
			t.Fatalf("size %d: proto %d", size, got.proto)
		}
		if binary.BigEndian.Uint16(got.l4[6:]) == 0 {
			t.Errorf("size %d: checksum still zero", size)
		}
		verifyL4(t, got)
	}
}

func TestEgressUDPZeroChecksumFragmentDropped(t *testing.T) {
	p := loadTestPrograms(t)
	dg := udp(1234, 4321, bytes.Repeat([]byte{1}, 100))
	in := frame4(testPod4, testDst4, protoUDP, dg, ip4opts{ttl: 64, id: 9, flags: 0x2000})
	ret, _ := runEgress(t, p, in)
	expectShot(t, ret)
}

func TestEgressICMPEcho(t *testing.T) {
	p := loadTestPrograms(t)
	msg := icmp(8, 0, 0x00010001, bytes.Repeat([]byte{0x42}, 56))
	in := packet4(testPod4, testDst4, protoICMP, msg, ip4opts{ttl: 64, id: 0xabcd, flags: 0x4000})
	ret, out := runEgress(t, p, in)
	expectOK(t, ret)
	got := parse(t, out)
	if got.proto != protoICMPv6 || got.l4[0] != 128 || got.l4[1] != 0 {
		t.Fatalf("not an echo request: proto=%d type=%d", got.proto, got.l4[0])
	}
	verifyL4(t, got)
	msg6 := append([]byte(nil), msg...)
	msg6[0] = 128
	want := packet6(testPod6, mapped(testDst4), 0, 64, protoICMPv6, msg6)
	copy(want[0:12], out[0:12])
	expectFrame(t, out, want)
}

func TestEgressICMPErrorDropped(t *testing.T) {
	p := loadTestPrograms(t)
	msg := icmp(3, 3, 0, make([]byte, 28))
	in := packet4(testPod4, testDst4, protoICMP, msg, ip4opts{ttl: 64})
	ret, _ := runEgress(t, p, in)
	expectShot(t, ret)
}

func TestEgressFragments(t *testing.T) {
	p := loadTestPrograms(t)
	// A 1600-byte UDP datagram split at 1480: first fragment carries the
	// UDP header, second carries the tail. The UDP checksum covers the
	// whole datagram and lives in the first fragment.
	payload := bytes.Repeat([]byte{7}, 1592)
	whole := udp(2000, 3000, payload)
	setCsum(whole, protoUDP, pseudo4(testPod4, testDst4, protoUDP, len(whole)))
	first := frame4(testPod4, testDst4, protoUDP, whole[:1480], ip4opts{ttl: 64, id: 0x4242, flags: 0x2000})
	second := frame4(testPod4, testDst4, protoUDP, whole[1480:], ip4opts{ttl: 64, id: 0x4242, flags: 1480 / 8})

	ret, out1 := runEgress(t, p, first)
	expectOK(t, ret)
	g1 := parse(t, out1)
	if !g1.frag || g1.fragOff != 0 || !g1.fragMore || g1.fragID != 0x4242 || g1.proto != protoUDP {
		t.Fatalf("first fragment: %+v", g1)
	}
	ret, out2 := runEgress(t, p, second)
	expectOK(t, ret)
	g2 := parse(t, out2)
	if !g2.frag || g2.fragOff != 1480/8 || g2.fragMore || g2.fragID != 0x4242 || g2.proto != protoUDP {
		t.Fatalf("second fragment: %+v", g2)
	}
	// Reassemble and verify the UDP checksum against the IPv6 pseudo-header.
	datagram := append(append([]byte(nil), g1.l4...), g2.l4...)
	if c := csum(pseudo6(g1.src, g1.dst, protoUDP, len(datagram)), datagram); c != 0 {
		t.Errorf("reassembled UDP checksum residual %#04x", c)
	}
	if len(datagram) != len(whole) {
		t.Errorf("reassembled %d bytes, want %d", len(datagram), len(whole))
	}
}

func TestEgressFragmentedICMPDropped(t *testing.T) {
	p := loadTestPrograms(t)
	msg := icmp(8, 0, 1, bytes.Repeat([]byte{1}, 1472))
	in := frame4(testPod4, testDst4, protoICMP, msg, ip4opts{ttl: 64, id: 3, flags: 0x2000})
	ret, _ := runEgress(t, p, in)
	expectShot(t, ret)
}

func TestEgressIPv4Options(t *testing.T) {
	p := loadTestPrograms(t)
	seg := tcp(40000, 443, 0x02, nil)

	// NOP NOP NOP EOL: stripped.
	in := packet4(testPod4, testDst4, protoTCP, seg, ip4opts{ttl: 64, flags: 0x4000, options: []byte{1, 1, 1, 0}})
	ret, out := runEgress(t, p, in)
	expectOK(t, ret)
	got := parse(t, out)
	verifyL4(t, got)
	want := packet6(testPod6, mapped(testDst4), 0, 64, protoTCP, seg)
	copy(want[0:12], out[0:12])
	expectFrame(t, out, want)

	// Loose source route: dropped.
	in = packet4(testPod4, testDst4, protoTCP, seg, ip4opts{ttl: 64, flags: 0x4000, options: []byte{131, 7, 4, 10, 0, 0, 1, 0}})
	ret, _ = runEgress(t, p, in)
	expectShot(t, ret)
}

func TestEgressDrops(t *testing.T) {
	p := loadTestPrograms(t)
	seg := tcp(1, 2, 0, nil)
	cases := map[string][]byte{
		"wrong source":  packet4(netip.MustParseAddr("10.0.0.1"), testDst4, protoTCP, seg, ip4opts{ttl: 64}),
		"multicast dst": packet4(testPod4, netip.MustParseAddr("224.0.0.251"), protoUDP, udp(5353, 5353, nil), ip4opts{ttl: 1}),
		"broadcast dst": packet4(testPod4, netip.MustParseAddr("255.255.255.255"), protoUDP, udp(68, 67, nil), ip4opts{ttl: 64}),
	}
	for name, in := range cases {
		ret, _ := runEgress(t, p, in)
		if ret != tcActShot {
			t.Errorf("%s: return %d, want TC_ACT_SHOT", name, ret)
		}
	}
}

func TestEgressPassThroughIPv6(t *testing.T) {
	p := loadTestPrograms(t)
	in := packet6(testPod6, netip.MustParseAddr("2001:db8::1"), 0, 64, protoTCP, tcp(1, 2, 0, nil))
	ret, out := runEgress(t, p, in)
	expectOK(t, ret)
	expectFrame(t, out, in)
}

func TestIngressTCP(t *testing.T) {
	p := loadTestPrograms(t)
	seg := tcp(80, 40000, 0x12, []byte("hello back"))
	in := packet6(mapped(testDst4), testPod6, 0x28, 57, protoTCP, seg)
	ret, out := runIngress(t, p, in)
	expectOK(t, ret)
	got := parse(t, out)
	if got.etherType != etherIP4 || got.version != 4 {
		t.Fatalf("not IPv4: %+v", got)
	}
	if got.src != testDst4 || got.dst != testPod4 || got.proto != protoTCP || got.hop != 57 || got.tc != 0x28 || !got.df || got.frag {
		t.Errorf("header: %+v", got)
	}
	verifyL4(t, got)
	want := packet4(testDst4, testPod4, protoTCP, seg, ip4opts{tos: 0x28, ttl: 57, flags: 0x4000})
	copy(want[0:12], out[0:12])
	expectFrame(t, out, want)
	c, _ := ReadCounters(p.Counters())
	if c["ingress_translated"] != 1 {
		t.Errorf("ingress_translated = %d", c["ingress_translated"])
	}
}

func TestIngressUDP(t *testing.T) {
	p := loadTestPrograms(t)
	dg := udp(53, 5353, []byte("dns reply"))
	in := packet6(mapped(testDst4), testPod6, 0, 60, protoUDP, dg)
	ret, out := runIngress(t, p, in)
	expectOK(t, ret)
	got := parse(t, out)
	verifyL4(t, got)
	want := packet4(testDst4, testPod4, protoUDP, dg, ip4opts{ttl: 60, flags: 0x4000})
	copy(want[0:12], out[0:12])
	expectFrame(t, out, want)

	// Zero UDP checksum is illegal over IPv6.
	bad := append([]byte(nil), in...)
	bad[ethLen+ip6Len+6], bad[ethLen+ip6Len+7] = 0, 0
	ret, _ = runIngress(t, p, bad)
	expectShot(t, ret)
}

func TestIngressEchoReply(t *testing.T) {
	p := loadTestPrograms(t)
	msg := icmp(129, 0, 0x00010001, bytes.Repeat([]byte{0x42}, 56))
	in := packet6(mapped(testDst4), testPod6, 0, 59, protoICMPv6, msg)
	ret, out := runIngress(t, p, in)
	expectOK(t, ret)
	got := parse(t, out)
	if got.proto != protoICMP || got.l4[0] != 0 {
		t.Fatalf("not an echo reply: %+v", got)
	}
	verifyL4(t, got)
	msg4 := append([]byte(nil), msg...)
	msg4[0] = 0
	want := packet4(testDst4, testPod4, protoICMP, msg4, ip4opts{ttl: 59, flags: 0x4000})
	copy(want[0:12], out[0:12])
	expectFrame(t, out, want)
}

func TestIngressFragments(t *testing.T) {
	p := loadTestPrograms(t)
	payload := bytes.Repeat([]byte{9}, 1592)
	whole := udp(3000, 2000, payload)
	setCsum(whole, protoUDP, pseudo6(mapped(testDst4), testPod6, protoUDP, len(whole)))
	mk := func(chunk []byte, off8 uint16, more bool) []byte {
		return concat(eth(etherIP6, macPod, macPeer),
			ip6(mapped(testDst4), testPod6, 0, 60, protoFrag, fragLen+len(chunk)),
			fragHdr(protoUDP, off8, more, 0x00015555), chunk)
	}
	ret, out1 := runIngress(t, p, mk(whole[:1232], 0, true))
	expectOK(t, ret)
	g1 := parse(t, out1)
	if !g1.fragMore || g1.fragOff != 0 || g1.fragID != 0x5555 || g1.df || g1.proto != protoUDP {
		t.Fatalf("first fragment: %+v", g1)
	}
	ret, out2 := runIngress(t, p, mk(whole[1232:], 1232/8, false))
	expectOK(t, ret)
	g2 := parse(t, out2)
	if g2.fragMore || g2.fragOff != 1232/8 || g2.fragID != 0x5555 || g2.df {
		t.Fatalf("second fragment: %+v", g2)
	}
	datagram := append(append([]byte(nil), g1.l4...), g2.l4...)
	if c := csum(pseudo4(g1.src, g1.dst, protoUDP, len(datagram)), datagram); c != 0 {
		t.Errorf("reassembled UDP checksum residual %#04x", c)
	}
}

func TestIngressFragmentedICMPDropped(t *testing.T) {
	p := loadTestPrograms(t)
	in := concat(eth(etherIP6, macPod, macPeer),
		ip6(mapped(testDst4), testPod6, 0, 60, protoFrag, fragLen+1000),
		fragHdr(protoICMPv6, 0, true, 1), icmp(129, 0, 1, make([]byte, 992)))
	ret, _ := runIngress(t, p, in)
	expectShot(t, ret)
}

func TestIngressExtensionHeaderDropped(t *testing.T) {
	p := loadTestPrograms(t)
	hbh := []byte{protoTCP, 0, 1, 4, 0, 0, 0, 0} // Hop-by-Hop, PadN
	seg := tcp(1, 2, 0, nil)
	in := concat(eth(etherIP6, macPod, macPeer),
		ip6(mapped(testDst4), testPod6, 0, 60, 0, len(hbh)+len(seg)), hbh, seg)
	ret, _ := runIngress(t, p, in)
	expectShot(t, ret)
}

func TestIngressPassThrough(t *testing.T) {
	p := loadTestPrograms(t)
	cases := map[string][]byte{
		"native ipv6 to pod":    packet6(netip.MustParseAddr("2001:db8::1"), testPod6, 0, 64, protoTCP, tcp(1, 2, 0, nil)),
		"dns64 prefix to pod":   packet6(netip.MustParseAddr("64:ff9b::c633:640a"), testPod6, 0, 64, protoTCP, tcp(1, 2, 0, nil)),
		"clat prefix other dst": packet6(mapped(testDst4), netip.MustParseAddr("2001:db8::9"), 0, 64, protoTCP, tcp(1, 2, 0, nil)),
		"ndp":                   packet6(netip.MustParseAddr("fe80::1"), testPod6, 0, 255, protoICMPv6, icmp(135, 0, 0, make([]byte, 16))),
		"native ipv6 ptb":       packet6(testRtr6, testPod6, 0, 64, protoICMPv6, icmp(2, 0, 1280, concat(ip6(testPod6, netip.MustParseAddr("2001:db8::9"), 0, 64, protoTCP, 20), tcp(1, 2, 0, nil)))),
		"native ipv6 echo":      packet6(testRtr6, testPod6, 0, 64, protoICMPv6, icmp(129, 0, 1, make([]byte, 56))),
		"router error not ours": packet6(testRtr6, testPod6, 0, 64, protoICMPv6, icmp(3, 0, 0, concat(ip6(netip.MustParseAddr("2001:db8::7"), mapped(testDst4), 0, 64, protoTCP, 20), tcp(1, 2, 0, nil)))),
		"ipv4 frame":            packet4(testDst4, testPod4, protoTCP, tcp(1, 2, 0, nil), ip4opts{ttl: 64}),
	}
	for name, in := range cases {
		ret, out := runIngress(t, p, in)
		if ret != tcActOK {
			t.Errorf("%s: return %d", name, ret)
		}
		if !bytes.Equal(out, in) {
			t.Errorf("%s: frame modified", name)
		}
	}
}

// embedded builds the packet that an ICMPv6 error quotes: what the pod sent.
func embedded(t *testing.T, proto uint8, l4 []byte, withFrag bool) []byte {
	t.Helper()
	l4 = append([]byte(nil), l4...)
	setCsum(l4, proto, pseudo6(testPod6, mapped(testDst4), proto, len(l4)))
	if withFrag {
		return concat(ip6(testPod6, mapped(testDst4), 0, 64, protoFrag, fragLen+len(l4)),
			fragHdr(proto, 0, true, 0x77), l4)
	}
	return concat(ip6(testPod6, mapped(testDst4), 0, 64, proto, len(l4)), l4)
}

func icmp6Error(typ, code uint8, rest uint32, inner []byte) []byte {
	return packet6(mapped(testRtr4), testPod6, 0, 60, protoICMPv6, icmp(typ, code, rest, inner))
}

func checkError(t *testing.T, out []byte, wantType, wantCode uint8) parsed {
	t.Helper()
	got := parse(t, out)
	if got.proto != protoICMP {
		t.Fatalf("outer proto %d", got.proto)
	}
	if got.src != testRtr4 || got.dst != testPod4 {
		t.Errorf("outer addresses %s -> %s", got.src, got.dst)
	}
	if got.l4[0] != wantType || got.l4[1] != wantCode {
		t.Errorf("ICMP type/code %d/%d, want %d/%d", got.l4[0], got.l4[1], wantType, wantCode)
	}
	verifyL4(t, got) // outer ICMPv4 checksum
	inner := parseQuoted(t, concat(eth(etherIP4, nil, nil), got.l4[8:]))
	if inner.src != testPod4 || inner.dst != testDst4 {
		t.Errorf("inner addresses %s -> %s", inner.src, inner.dst)
	}
	return inner
}

func TestIngressPacketTooBig(t *testing.T) {
	p := loadTestPrograms(t)
	seg := tcp(40000, 80, 0x10, bytes.Repeat([]byte{3}, 200))
	inner := embedded(t, protoTCP, seg, false)
	ret, out := runIngress(t, p, icmp6Error(2, 0, 1280, inner))
	expectOK(t, ret)
	in4 := checkError(t, out, 3, 4)
	got := parse(t, out)
	if mtu := binary.BigEndian.Uint16(got.l4[6:]); mtu != 1260 {
		t.Errorf("MTU %d, want 1260", mtu)
	}
	if in4.proto != protoTCP || in4.totalLen != ip4Len+len(seg) || in4.hop != 64 || !in4.df {
		t.Errorf("inner header: %+v", in4)
	}
	verifyL4(t, in4) // inner TCP checksum was rewritten for the IPv4 pseudo-header
	if !bytes.Equal(in4.l4[:16], seg[:16]) || !bytes.Equal(in4.l4[18:], seg[18:]) {
		t.Errorf("inner TCP bytes changed")
	}
}

func TestIngressPacketTooBigWithInnerFragment(t *testing.T) {
	p := loadTestPrograms(t)
	dg := udp(1000, 2000, bytes.Repeat([]byte{4}, 64))
	inner := embedded(t, protoUDP, dg, true)
	ret, out := runIngress(t, p, icmp6Error(2, 0, 1400, inner))
	expectOK(t, ret)
	in4 := checkError(t, out, 3, 4)
	got := parse(t, out)
	if mtu := binary.BigEndian.Uint16(got.l4[6:]); mtu != 1400-28 {
		t.Errorf("MTU %d, want %d", mtu, 1400-28)
	}
	if !in4.fragMore || in4.fragOff != 0 || in4.fragID != 0x77 || in4.df || in4.proto != protoUDP {
		t.Errorf("inner fragment fields: %+v", in4)
	}
	if in4.totalLen != ip4Len+len(dg) {
		t.Errorf("inner total length %d, want %d", in4.totalLen, ip4Len+len(dg))
	}
}

func TestIngressErrorMapping(t *testing.T) {
	p := loadTestPrograms(t)
	seg := tcp(40000, 80, 0x02, nil)
	inner := embedded(t, protoTCP, seg, false)
	cases := []struct {
		name   string
		t6, c6 uint8
		rest   uint32
		t4, c4 uint8
	}{
		{"no route", 1, 0, 0, 3, 1},
		{"admin prohibited", 1, 1, 0, 3, 10},
		{"address unreachable", 1, 3, 0, 3, 1},
		{"port unreachable", 1, 4, 0, 3, 3},
		{"hop limit exceeded", 3, 0, 0, 11, 0},
		{"reassembly time exceeded", 3, 1, 0, 11, 1},
		{"param problem hop limit", 4, 0, 7, 12, 0},
		{"unknown next header", 4, 1, 6, 3, 2},
	}
	for _, c := range cases {
		ret, out := runIngress(t, p, icmp6Error(c.t6, c.c6, c.rest, inner))
		if ret != tcActOK {
			t.Errorf("%s: return %d", c.name, ret)
			continue
		}
		in4 := checkError(t, out, c.t4, c.c4)
		verifyL4(t, in4)
		if c.t4 == 12 {
			got := parse(t, out)
			if got.l4[4] != 8 {
				t.Errorf("%s: pointer %d, want 8", c.name, got.l4[4])
			}
		}
	}

	// Unmappable errors are dropped, not forwarded as garbage.
	for name, in := range map[string][]byte{
		"unrecognised option": icmp6Error(4, 2, 0, inner),
		"unmapped pointer":    icmp6Error(4, 0, 5, inner),
		"inner not from pod":  icmp6Error(3, 0, 0, concat(ip6(netip.MustParseAddr("2001:db8::7"), mapped(testDst4), 0, 64, protoTCP, len(seg)), seg)),
		"multicast listener":  packet6(mapped(testRtr4), testPod6, 0, 1, protoICMPv6, icmp(130, 0, 0, make([]byte, 20))),
	} {
		ret, _ := runIngress(t, p, in)
		if ret != tcActShot {
			t.Errorf("%s: return %d, want TC_ACT_SHOT", name, ret)
		}
	}
}

func TestIngressErrorWithInnerICMP(t *testing.T) {
	p := loadTestPrograms(t)
	msg := icmp(128, 0, 0x00010002, bytes.Repeat([]byte{5}, 32))
	inner := embedded(t, protoICMPv6, msg, false)
	ret, out := runIngress(t, p, icmp6Error(3, 0, 0, inner))
	expectOK(t, ret)
	in4 := checkError(t, out, 11, 0)
	if in4.proto != protoICMP {
		t.Fatalf("inner proto %d", in4.proto)
	}
	// Linux ping sockets only accept errors quoting ICMP_ECHO (8).
	if in4.l4[0] != 8 || in4.l4[1] != 0 {
		t.Errorf("inner ICMP type/code %d/%d, want 8/0", in4.l4[0], in4.l4[1])
	}
	verifyL4(t, in4) // inner ICMPv4 checksum without the pseudo-header
	if !bytes.Equal(in4.l4[4:], msg[4:]) {
		t.Errorf("inner ICMP identifier/sequence/payload changed")
	}
}

// TestIngressErrorFromRouter: an ICMPv6 error from a router on the IPv6 path
// has a source outside the CLAT prefix. It must still be translated when it
// quotes a CLAT flow, with the RFC 7335 dummy address as the IPv4 source.
func TestIngressErrorFromRouter(t *testing.T) {
	p := loadTestPrograms(t)
	seg := tcp(40000, 80, 0x10, bytes.Repeat([]byte{3}, 1200))
	inner := embedded(t, protoTCP, seg, false)
	// Routers quote as much as fits in 1280 bytes.
	inner = inner[:1280-ip6Len-8]
	in := packet6(testRtr6, testPod6, 0, 63, protoICMPv6, icmp(2, 0, 1280, inner))
	ret, out := runIngress(t, p, in)
	expectOK(t, ret)
	got := parse(t, out)
	if got.proto != protoICMP || got.src != testErr4 || got.dst != testPod4 {
		t.Fatalf("outer: %+v", got)
	}
	if got.l4[0] != 3 || got.l4[1] != 4 || binary.BigEndian.Uint16(got.l4[6:]) != 1260 {
		t.Errorf("ICMP %d/%d mtu %d, want 3/4 mtu 1260", got.l4[0], got.l4[1], binary.BigEndian.Uint16(got.l4[6:]))
	}
	verifyL4(t, got)
	in4 := parseQuoted(t, concat(eth(etherIP4, nil, nil), got.l4[8:]))
	if in4.src != testPod4 || in4.dst != testDst4 || in4.proto != protoTCP || in4.totalLen != ip4Len+len(seg) {
		t.Errorf("inner: %+v", in4)
	}

	// Same for an echo request quoted by a Time Exceeded from a router.
	msg := icmp(128, 0, 0x00010002, bytes.Repeat([]byte{5}, 1400))
	inner = embedded(t, protoICMPv6, msg, false)[:1280-ip6Len-8]
	ret, out = runIngress(t, p, packet6(testRtr6, testPod6, 0, 64, protoICMPv6, icmp(3, 0, 0, inner)))
	expectOK(t, ret)
	got = parse(t, out)
	if got.src != testErr4 || got.l4[0] != 11 {
		t.Fatalf("outer: %+v", got)
	}
	verifyL4(t, got)
	in4 = parseQuoted(t, concat(eth(etherIP4, nil, nil), got.l4[8:]))
	if in4.proto != protoICMP || in4.l4[0] != 8 || binary.BigEndian.Uint16(in4.l4[4:]) != 1 {
		t.Errorf("inner ICMP: type %d id %d", in4.l4[0], binary.BigEndian.Uint16(in4.l4[4:]))
	}
}

// TestRoundTrip sends a TCP segment out, mirrors it as the server's reply and
// brings it back in: the pod must see the exact reverse of what it sent.
func TestRoundTrip(t *testing.T) {
	p := loadTestPrograms(t)
	seg := tcp(40000, 80, 0x18, []byte("GET / HTTP/1.0\r\n\r\n"))
	in := packet4(testPod4, testDst4, protoTCP, seg, ip4opts{tos: 0x10, ttl: 64, flags: 0x4000})
	ret, out6 := runEgress(t, p, in)
	expectOK(t, ret)

	// "Reply": swap addresses at both layers, keep everything else.
	reply := append([]byte(nil), out6...)
	copy(reply[0:6], out6[6:12])
	copy(reply[6:12], out6[0:6])
	copy(reply[ethLen+8:ethLen+24], out6[ethLen+24:ethLen+40])
	copy(reply[ethLen+24:ethLen+40], out6[ethLen+8:ethLen+24])
	copy(reply[ethLen+ip6Len:ethLen+ip6Len+2], out6[ethLen+ip6Len+2:ethLen+ip6Len+4])
	copy(reply[ethLen+ip6Len+2:ethLen+ip6Len+4], out6[ethLen+ip6Len:ethLen+ip6Len+2])
	// Swapping the addresses and ports keeps the checksum valid.
	verifyL4(t, parse(t, reply))

	ret, out4 := runIngress(t, p, reply)
	expectOK(t, ret)
	got := parse(t, out4)
	verifyL4(t, got)
	if got.src != testDst4 || got.dst != testPod4 || got.tc != 0x10 || got.hop != 64 {
		t.Errorf("round trip header: %+v", got)
	}
	if !bytes.Equal(got.l4[20:], seg[20:]) {
		t.Errorf("payload changed")
	}
}
