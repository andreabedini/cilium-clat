package clat

// Packet builders and checkers for the BPF_PROG_TEST_RUN tests. They are the
// oracle: an output packet must carry checksums that verify with the plain
// RFC 1071 arithmetic below, and header fields that match what an independent
// Go builder produces for the same flow.

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"testing"
)

const (
	ethLen   = 14
	ip4Len   = 20
	ip6Len   = 40
	fragLen  = 8
	etherIP4 = 0x0800
	etherIP6 = 0x86dd

	protoICMP   = 1
	protoTCP    = 6
	protoUDP    = 17
	protoFrag   = 44
	protoICMPv6 = 58

	tcActOK   = 0
	tcActShot = 2
)

var (
	macPod  = []byte{0x02, 0, 0, 0, 0, 0x02}
	macPeer = []byte{0x02, 0, 0, 0, 0, 0x01}

	testPrefix = netip.MustParsePrefix("64:ff9b:1::/96")
	testPod6   = netip.MustParseAddr("2001:db8:cafe::2")
	testPod4   = netip.MustParseAddr("192.0.0.2")
	testDst4   = netip.MustParseAddr("198.51.100.10")
	testRtr4   = netip.MustParseAddr("203.0.113.1")
	testRtr6   = netip.MustParseAddr("2001:db8:1::1") // a router outside P
	testErr4   = netip.MustParseAddr("192.0.0.8")
)

// mapped returns P::a.b.c.d.
func mapped(a netip.Addr) netip.Addr {
	b := testPrefix.Addr().As16()
	copy(b[12:], a.AsSlice())
	return netip.AddrFrom16(b)
}

func sum16(data []byte) uint32 {
	var s uint32
	for i := 0; i+1 < len(data); i += 2 {
		s += uint32(binary.BigEndian.Uint16(data[i:]))
	}
	if len(data)%2 == 1 {
		s += uint32(data[len(data)-1]) << 8
	}
	return s
}

func fold(s uint32) uint16 {
	for s > 0xffff {
		s = (s & 0xffff) + (s >> 16)
	}
	return uint16(s)
}

// csum returns the RFC 1071 checksum of the concatenation of the buffers.
func csum(bufs ...[]byte) uint16 {
	var s uint32
	for _, b := range bufs {
		s += sum16(b)
	}
	return ^fold(s)
}

func pseudo4(src, dst netip.Addr, proto uint8, l4len int) []byte {
	b := make([]byte, 12)
	copy(b[0:], src.AsSlice())
	copy(b[4:], dst.AsSlice())
	b[9] = proto
	binary.BigEndian.PutUint16(b[10:], uint16(l4len))
	return b
}

func pseudo6(src, dst netip.Addr, nh uint8, l4len int) []byte {
	b := make([]byte, 40)
	copy(b[0:], src.AsSlice())
	copy(b[16:], dst.AsSlice())
	binary.BigEndian.PutUint32(b[32:], uint32(l4len))
	b[39] = nh
	return b
}

func eth(proto uint16, dst, src []byte) []byte {
	b := make([]byte, ethLen)
	copy(b[0:], dst)
	copy(b[6:], src)
	binary.BigEndian.PutUint16(b[12:], proto)
	return b
}

type ip4opts struct {
	tos     uint8
	ttl     uint8
	id      uint16
	flags   uint16 // IP_DF, IP_MF, offset
	options []byte // multiple of 4
}

// ip4 builds an IPv4 header with a valid checksum.
func ip4(src, dst netip.Addr, proto uint8, payloadLen int, o ip4opts) []byte {
	hl := ip4Len + len(o.options)
	b := make([]byte, hl)
	b[0] = 0x40 | uint8(hl/4)
	b[1] = o.tos
	binary.BigEndian.PutUint16(b[2:], uint16(hl+payloadLen))
	binary.BigEndian.PutUint16(b[4:], o.id)
	binary.BigEndian.PutUint16(b[6:], o.flags)
	b[8] = o.ttl
	b[9] = proto
	copy(b[12:], src.AsSlice())
	copy(b[16:], dst.AsSlice())
	copy(b[20:], o.options)
	binary.BigEndian.PutUint16(b[10:], csum(b))
	return b
}

func ip6(src, dst netip.Addr, tc, hop, nh uint8, payloadLen int) []byte {
	b := make([]byte, ip6Len)
	binary.BigEndian.PutUint32(b[0:], 6<<28|uint32(tc)<<20)
	binary.BigEndian.PutUint16(b[4:], uint16(payloadLen))
	b[6] = nh
	b[7] = hop
	copy(b[8:], src.AsSlice())
	copy(b[24:], dst.AsSlice())
	return b
}

func fragHdr(nh uint8, offset8 uint16, more bool, id uint32) []byte {
	b := make([]byte, fragLen)
	b[0] = nh
	fo := offset8 << 3
	if more {
		fo |= 1
	}
	binary.BigEndian.PutUint16(b[2:], fo)
	binary.BigEndian.PutUint32(b[4:], id)
	return b
}

func tcp(sport, dport uint16, flags uint8, payload []byte) []byte {
	b := make([]byte, 20+len(payload))
	binary.BigEndian.PutUint16(b[0:], sport)
	binary.BigEndian.PutUint16(b[2:], dport)
	binary.BigEndian.PutUint32(b[4:], 0x11223344)
	binary.BigEndian.PutUint32(b[8:], 0x55667788)
	b[12] = 5 << 4
	b[13] = flags
	binary.BigEndian.PutUint16(b[14:], 65535)
	copy(b[20:], payload)
	return b
}

func udp(sport, dport uint16, payload []byte) []byte {
	b := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(b[0:], sport)
	binary.BigEndian.PutUint16(b[2:], dport)
	binary.BigEndian.PutUint16(b[4:], uint16(len(b)))
	copy(b[8:], payload)
	return b
}

func icmp(typ, code uint8, rest uint32, payload []byte) []byte {
	b := make([]byte, 8+len(payload))
	b[0] = typ
	b[1] = code
	binary.BigEndian.PutUint32(b[4:], rest)
	copy(b[8:], payload)
	return b
}

func setCsum(l4 []byte, proto uint8, pseudo []byte) {
	off := csumOffset(proto)
	if off < 0 {
		return
	}
	l4[off], l4[off+1] = 0, 0
	c := csum(pseudo, l4)
	if proto == protoUDP && c == 0 {
		c = 0xffff
	}
	binary.BigEndian.PutUint16(l4[off:], c)
}

func csumOffset(proto uint8) int {
	switch proto {
	case protoTCP:
		return 16
	case protoUDP:
		return 6
	case protoICMP, protoICMPv6:
		return 2
	}
	return -1
}

// packet4 builds a complete, unfragmented IPv4 frame from the pod with a
// correct transport checksum.
func packet4(src, dst netip.Addr, proto uint8, l4 []byte, o ip4opts) []byte {
	l4 = append([]byte(nil), l4...)
	if proto == protoICMP {
		setCsum(l4, proto, nil)
	} else {
		setCsum(l4, proto, pseudo4(src, dst, proto, len(l4)))
	}
	return frame4(src, dst, proto, l4, o)
}

// frame4 builds an IPv4 frame without touching the transport bytes.
func frame4(src, dst netip.Addr, proto uint8, l4 []byte, o ip4opts) []byte {
	return concat(eth(etherIP4, macPeer, macPod), ip4(src, dst, proto, len(l4), o), l4)
}

// packet6 builds a complete IPv6 frame with correct checksums.
func packet6(src, dst netip.Addr, tc, hop, nh uint8, l4 []byte) []byte {
	l4 = append([]byte(nil), l4...)
	setCsum(l4, nh, pseudo6(src, dst, nh, len(l4)))
	return concat(eth(etherIP6, macPod, macPeer), ip6(src, dst, tc, hop, nh, len(l4)), l4)
}

func concat(bufs ...[]byte) []byte {
	var out []byte
	for _, b := range bufs {
		out = append(out, b...)
	}
	return out
}

// parsed is the decoded view of a frame used by the checkers.
type parsed struct {
	etherType uint16
	version   int
	src, dst  netip.Addr
	proto     uint8 // upper-layer protocol after extension headers
	hop       uint8
	tc        uint8
	hdrLen    int // bytes before the L4 header (from the frame start)
	l4        []byte
	frag      bool
	fragOff   uint16 // in 8-byte units
	fragMore  bool
	fragID    uint32
	df        bool
	totalLen  int // IPv4 total length or IPv6 payload length + 40
}

func parse(t *testing.T, b []byte) parsed {
	t.Helper()
	return parseFrame(t, b, false)
}

// parseQuoted parses the packet quoted inside an ICMP error. Routers
// truncate the quote, but its IP header keeps the original total length
// (RFC 7915 5.2), so the length check is skipped.
func parseQuoted(t *testing.T, b []byte) parsed {
	t.Helper()
	return parseFrame(t, b, true)
}

func parseFrame(t *testing.T, b []byte, quoted bool) parsed {
	t.Helper()
	if len(b) < ethLen {
		t.Fatalf("frame too short: %d", len(b))
	}
	p := parsed{etherType: binary.BigEndian.Uint16(b[12:])}
	switch p.etherType {
	case etherIP4:
		h := b[ethLen:]
		if len(h) < ip4Len {
			t.Fatalf("IPv4 header truncated")
		}
		p.version = int(h[0] >> 4)
		hl := int(h[0]&0xf) * 4
		if csum(h[:hl]) != 0 {
			t.Errorf("IPv4 header checksum invalid")
		}
		p.tc = h[1]
		p.totalLen = int(binary.BigEndian.Uint16(h[2:]))
		fl := binary.BigEndian.Uint16(h[6:])
		p.df = fl&0x4000 != 0
		p.fragMore = fl&0x2000 != 0
		p.fragOff = fl & 0x1fff
		p.frag = p.fragMore || p.fragOff != 0
		p.fragID = uint32(binary.BigEndian.Uint16(h[4:]))
		p.hop = h[8]
		p.proto = h[9]
		p.src = netip.AddrFrom4([4]byte(h[12:16]))
		p.dst = netip.AddrFrom4([4]byte(h[16:20]))
		p.hdrLen = ethLen + hl
		p.l4 = b[p.hdrLen:]
		if !quoted && p.totalLen != len(b)-ethLen {
			t.Errorf("IPv4 total length %d, frame carries %d", p.totalLen, len(b)-ethLen)
		}
	case etherIP6:
		h := b[ethLen:]
		if len(h) < ip6Len {
			t.Fatalf("IPv6 header truncated")
		}
		p.version = int(h[0] >> 4)
		p.tc = uint8(binary.BigEndian.Uint32(h[0:]) >> 20)
		p.totalLen = int(binary.BigEndian.Uint16(h[4:])) + ip6Len
		p.proto = h[6]
		p.hop = h[7]
		p.src = netip.AddrFrom16([16]byte(h[8:24]))
		p.dst = netip.AddrFrom16([16]byte(h[24:40]))
		p.hdrLen = ethLen + ip6Len
		if p.proto == protoFrag {
			f := b[p.hdrLen:]
			p.frag = true
			p.proto = f[0]
			fo := binary.BigEndian.Uint16(f[2:])
			p.fragOff = fo >> 3
			p.fragMore = fo&1 != 0
			p.fragID = binary.BigEndian.Uint32(f[4:])
			p.hdrLen += fragLen
		}
		p.l4 = b[p.hdrLen:]
		if !quoted && p.totalLen != len(b)-ethLen {
			t.Errorf("IPv6 payload length %d, frame carries %d", p.totalLen-ip6Len, len(b)-ethLen-ip6Len)
		}
	default:
		t.Fatalf("unexpected ethertype %#x", p.etherType)
	}
	return p
}

// verifyL4 checks the transport checksum of a parsed, unfragmented (or first
// fragment of a fully present) packet.
func verifyL4(t *testing.T, p parsed) {
	t.Helper()
	if p.frag && (p.fragOff != 0 || p.fragMore) {
		return // needs the whole datagram
	}
	var pseudo []byte
	switch {
	case p.etherType == etherIP4 && p.proto == protoICMP:
		pseudo = nil
	case p.etherType == etherIP4:
		pseudo = pseudo4(p.src, p.dst, p.proto, len(p.l4))
	default:
		pseudo = pseudo6(p.src, p.dst, p.proto, len(p.l4))
	}
	off := csumOffset(p.proto)
	if off < 0 {
		return
	}
	field := binary.BigEndian.Uint16(p.l4[off:])
	if p.proto == protoUDP && field == 0 {
		if p.etherType == etherIP6 {
			t.Errorf("UDP over IPv6 with zero checksum")
		}
		return
	}
	if c := csum(pseudo, p.l4); c != 0 {
		t.Errorf("%s checksum invalid (residual %#04x, field %#04x)", protoName(p.proto), c, field)
	}
}

func protoName(p uint8) string {
	switch p {
	case protoTCP:
		return "TCP"
	case protoUDP:
		return "UDP"
	case protoICMP:
		return "ICMP"
	case protoICMPv6:
		return "ICMPv6"
	}
	return fmt.Sprintf("proto %d", p)
}
