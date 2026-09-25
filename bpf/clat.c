// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/*
 * cilium-clat: stateless CLAT (RFC 6877 / RFC 7915) for the pod side of a
 * veth pair.
 *
 * clat_egress  runs on the clsact egress hook of the pod eth0 and rewrites
 *              IPv4 packets from POD_IP4 into IPv6 packets from POD_IP6 to
 *              CLAT_PREFIX::a.b.c.d.
 * clat_ingress runs on the clsact ingress hook of the pod eth0 and rewrites
 *              IPv6 packets from CLAT_PREFIX::a.b.c.d to POD_IP6 back into
 *              IPv4 packets from a.b.c.d to POD_IP4.
 *
 * Everything else passes untouched. The programs keep no state. The only map
 * is a per-CPU array of counters.
 *
 * Checksum strategy. All header bytes are written with BPF_F_RECOMPUTE_CSUM
 * so that skb->csum stays valid for CHECKSUM_COMPLETE packets, and the L4
 * checksum field is patched with bpf_l4_csum_replace(BPF_F_PSEUDO_HDR) using
 * a difference computed by bpf_csum_diff. The kernel then does the right
 * thing for CHECKSUM_NONE, CHECKSUM_COMPLETE and CHECKSUM_PARTIAL. The
 * difference passed to the helper always includes the pseudo-header delta
 * plus, for ICMP, the in-packet bytes that changed.
 */
#include <stdbool.h>
#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include <linux/pkt_cls.h>

#include "bpf_helpers.h"
#include "bpf_endian.h"

/* From the kernel's net/ip.h, not exported to userspace. */
#define IP_DF 0x4000
#define IP_MF 0x2000
#define IP_OFFSET 0x1fff

/* From the kernel's net/ipv6.h, not exported to userspace. */
struct frag_hdr {
	__u8 nexthdr;
	__u8 reserved;
	__be16 frag_off;
	__be32 identification;
};

/* linux/icmp.h drags in libc headers, so define what is needed here. */
#define ICMP_ECHOREPLY 0
#define ICMP_DEST_UNREACH 3
#define ICMP_ECHO 8
#define ICMP_TIME_EXCEEDED 11
#define ICMP_PARAMETERPROB 12
#define ICMP_HOST_UNREACH 1
#define ICMP_PROT_UNREACH 2
#define ICMP_PORT_UNREACH 3
#define ICMP_FRAG_NEEDED 4
#define ICMP_HOST_ANO 10

struct icmphdr {
	__u8 type;
	__u8 code;
	__sum16 checksum;
	union {
		struct {
			__be16 id;
			__be16 sequence;
		} echo;
		__be32 gateway;
		struct {
			__be16 __unused;
			__be16 mtu;
		} frag;
	} un;
};

char _license[] SEC("license") = "Dual BSD/GPL";

/* Per-pod constants, set by the plugin before load. */
volatile const struct in6_addr CLAT_PREFIX; /* /96, low 32 bits zero */
volatile const struct in6_addr POD_IP6;
volatile const __be32 POD_IP4;
/* Source of ICMPv4 errors translated from ICMPv6 errors whose source is not
 * inside CLAT_PREFIX (routers on the IPv6 path). RFC 7335 dummy address
 * 192.0.0.8 by default. */
volatile const __be32 ERR_IP4;

/* Counter indexes. Keep in sync with internal/clat/counters.go. */
enum clat_counter {
	CNT_EGRESS_TRANSLATED = 0,
	CNT_INGRESS_TRANSLATED,
	CNT_EGRESS_DROP_TRUNCATED,
	CNT_EGRESS_DROP_BAD_SRC,
	CNT_EGRESS_DROP_MCAST,
	CNT_EGRESS_DROP_SRCROUTE,
	CNT_EGRESS_DROP_FRAG_NO_CSUM,
	CNT_EGRESS_DROP_ICMP_UNSUPPORTED,
	CNT_EGRESS_DROP_TOO_BIG,
	CNT_EGRESS_DROP_HELPER,
	CNT_INGRESS_DROP_TRUNCATED,
	CNT_INGRESS_DROP_EXTHDR,
	CNT_INGRESS_DROP_UDP_ZERO_CSUM,
	CNT_INGRESS_DROP_FRAG_ICMP,
	CNT_INGRESS_DROP_ICMP_UNSUPPORTED,
	CNT_INGRESS_DROP_ICMP_INNER,
	CNT_INGRESS_DROP_HELPER,
	CNT_MAX,
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, CNT_MAX);
	__type(key, __u32);
	__type(value, __u64);
} clat_counters SEC(".maps");

static __always_inline void count(__u32 key)
{
	__u64 *v = bpf_map_lookup_elem(&clat_counters, &key);
	if (v)
		(*v)++;
}

#define DROP(key)                                                              \
	({                                                                     \
		count(key);                                                    \
		TC_ACT_SHOT;                                                   \
	})

#define STORE_FLAGS BPF_F_RECOMPUTE_CSUM
#define ROOM_FLAGS (BPF_F_ADJ_ROOM_FIXED_GSO | BPF_F_ADJ_ROOM_NO_CSUM_RESET)

#define IP6_HLEN sizeof(struct ipv6hdr)
#define IP4_HLEN sizeof(struct iphdr)
#define FRAG_HLEN sizeof(struct frag_hdr)

/* Largest unfragmented datagram for which we compute a full UDP checksum. */
#define CSUM_CHUNK 256
#define CSUM_MAX_CHUNKS 40 /* 10240 bytes, above any sane pod MTU */

/* IPv4 option types that carry a source route. */
#define IPOPT_LSRR_T 131
#define IPOPT_SSRR_T 137

struct pseudo6 {
	struct in6_addr saddr;
	struct in6_addr daddr;
	__be32 len;
	__be32 nexthdr; /* zero-padded, protocol in the last byte */
};

static __always_inline __u16 csum_fold(__wsum csum)
{
	__u32 s = (__u32)csum;
	s = (s & 0xffff) + (s >> 16);
	s = (s & 0xffff) + (s >> 16);
	return (__u16)~s;
}

/* A 32-bit word whose first two bytes are v and last two are zero, in
 * packet byte order. Endian-safe. */
static __always_inline __be32 word16(__be16 v)
{
	__u8 b[4] = {};
	__be32 w;

	__builtin_memcpy(b, &v, sizeof(v));
	__builtin_memcpy(&w, b, sizeof(w));
	return w;
}

static __always_inline void prefix_copy(struct in6_addr *dst,
					volatile const struct in6_addr *src)
{
	dst->in6_u.u6_addr32[0] = src->in6_u.u6_addr32[0];
	dst->in6_u.u6_addr32[1] = src->in6_u.u6_addr32[1];
	dst->in6_u.u6_addr32[2] = src->in6_u.u6_addr32[2];
	dst->in6_u.u6_addr32[3] = src->in6_u.u6_addr32[3];
}

static __always_inline bool addr6_eq(const struct in6_addr *a,
				     volatile const struct in6_addr *b)
{
	return a->in6_u.u6_addr32[0] == b->in6_u.u6_addr32[0] &&
	       a->in6_u.u6_addr32[1] == b->in6_u.u6_addr32[1] &&
	       a->in6_u.u6_addr32[2] == b->in6_u.u6_addr32[2] &&
	       a->in6_u.u6_addr32[3] == b->in6_u.u6_addr32[3];
}

static __always_inline bool in_prefix(const struct in6_addr *a)
{
	return a->in6_u.u6_addr32[0] == CLAT_PREFIX.in6_u.u6_addr32[0] &&
	       a->in6_u.u6_addr32[1] == CLAT_PREFIX.in6_u.u6_addr32[1] &&
	       a->in6_u.u6_addr32[2] == CLAT_PREFIX.in6_u.u6_addr32[2];
}

/* Make sure the first len bytes are in the linear area. */
static __always_inline bool ensure_linear(struct __sk_buff *skb, __u32 len)
{
	if (skb->data_end - skb->data >= len)
		return true;
	if (bpf_skb_pull_data(skb, len) < 0)
		return false;
	return skb->data_end - skb->data >= len;
}

static __always_inline bool is_ext_hdr(__u8 nh)
{
	switch (nh) {
	case IPPROTO_HOPOPTS:
	case IPPROTO_ROUTING:
	case IPPROTO_FRAGMENT:
	case IPPROTO_DSTOPTS:
	case IPPROTO_AH:
	case IPPROTO_NONE:
	case IPPROTO_MH:
	case 139: /* HIP */
	case 140: /* Shim6 */
		return true;
	}
	return false;
}

/*
 * ---------------------------------------------------------------------------
 * Egress: IPv4 -> IPv6
 * ---------------------------------------------------------------------------
 */

/* Look for a source route option. Returns true when one is present or the
 * option list is malformed. Reads option bytes one at a time through the
 * helper: no stack array, so nothing for the verifier to prove about
 * variable-offset stack access. Options are rare on pod egress. */
static __noinline bool ip4_has_source_route(struct __sk_buff *skb, __u32 optoff,
					    __u32 optlen)
{
	__u32 i = 0, k;

	if (optlen < 4 || optlen > 40 || (optlen & 3))
		return true;

	for (k = 0; k < 40; k++) {
		__u8 t, l;

		if (i >= optlen)
			break;
		if (bpf_skb_load_bytes(skb, optoff + i, &t, sizeof(t)) < 0)
			return true;
		if (t == 0) /* end of option list */
			break;
		if (t == 1) { /* no-op */
			i++;
			continue;
		}
		if (t == IPOPT_LSRR_T || t == IPOPT_SSRR_T)
			return true;
		if (i + 1 >= optlen)
			return true; /* malformed: type without length */
		if (bpf_skb_load_bytes(skb, optoff + i + 1, &l, sizeof(l)) < 0)
			return true;
		if (l < 2)
			return true; /* malformed */
		i += l;
	}
	return false;
}

/* Full checksum of the UDP header + payload at l4off (ulen bytes) with the
 * IPv6 pseudo-header in seed. The checksum field must already be zero. */
static __noinline int udp_full_csum(struct __sk_buff *skb, __u32 l4off,
				    __u32 ulen, __wsum seed, __u16 *out)
{
	__u8 buf[CSUM_CHUNK];
	__wsum sum = seed;
	__u32 off = 0;
	__u32 tail;
	__u32 i;

	if (ulen > CSUM_CHUNK * CSUM_MAX_CHUNKS)
		return -1;

	/* Whole chunks. */
	for (i = 0; i < CSUM_MAX_CHUNKS; i++) {
		if (off + CSUM_CHUNK > ulen)
			break;
		if (bpf_skb_load_bytes(skb, l4off + off, buf, CSUM_CHUNK) < 0)
			return -1;
		sum = bpf_csum_diff(NULL, 0, (__be32 *)buf, CSUM_CHUNK, sum);
		off += CSUM_CHUNK;
	}

	/* Tail, zero-padded to a whole chunk. The mask gives the verifier a
	 * non-negative 64-bit range; the test gives it the non-zero lower
	 * bound the helper insists on. */
	tail = (ulen - off) & (CSUM_CHUNK - 1);
	if (tail != 0) {
		__builtin_memset(buf, 0, sizeof(buf));
		if (bpf_skb_load_bytes(skb, l4off + off, buf, tail) < 0)
			return -1;
		sum = bpf_csum_diff(NULL, 0, (__be32 *)buf, CSUM_CHUNK, sum);
	}

	*out = csum_fold(sum);
	if (*out == 0)
		*out = 0xffff;
	return 0;
}

SEC("tc")
int clat_egress(struct __sk_buff *skb)
{
	void *data, *data_end;
	struct ethhdr *eth;
	struct iphdr *ip4;
	struct ipv6hdr h6 = {};
	__be32 addr4[2];
	__u32 ihl, optlen, l4off, l4len;
	__u16 tot_len, id, frag_off;
	__u8 tos, ttl, proto, nh6;
	__be32 saddr, daddr;
	bool is_frag, first, mf;
	__wsum diff;

	data = (void *)(long)skb->data;
	data_end = (void *)(long)skb->data_end;
	eth = data;
	if ((void *)(eth + 1) > data_end)
		return TC_ACT_OK;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return TC_ACT_OK;

	if (!ensure_linear(skb, ETH_HLEN + IP4_HLEN))
		return DROP(CNT_EGRESS_DROP_TRUNCATED);
	data = (void *)(long)skb->data;
	data_end = (void *)(long)skb->data_end;
	ip4 = data + ETH_HLEN;
	if ((void *)(ip4 + 1) > data_end)
		return DROP(CNT_EGRESS_DROP_TRUNCATED);
	if (ip4->version != 4)
		return DROP(CNT_EGRESS_DROP_TRUNCATED);
	ihl = ip4->ihl * 4;
	if (ihl < IP4_HLEN)
		return DROP(CNT_EGRESS_DROP_TRUNCATED);

	saddr = ip4->saddr;
	daddr = ip4->daddr;
	if (saddr != POD_IP4)
		return DROP(CNT_EGRESS_DROP_BAD_SRC);
	/* Multicast and limited broadcast have no IPv6 mapping. */
	if ((daddr & bpf_htonl(0xf0000000)) == bpf_htonl(0xe0000000) ||
	    daddr == bpf_htonl(0xffffffff))
		return DROP(CNT_EGRESS_DROP_MCAST);

	tos = ip4->tos;
	ttl = ip4->ttl;
	proto = ip4->protocol;
	tot_len = bpf_ntohs(ip4->tot_len);
	id = ip4->id;
	frag_off = bpf_ntohs(ip4->frag_off);
	if (tot_len < ihl)
		return DROP(CNT_EGRESS_DROP_TRUNCATED);

	is_frag = (frag_off & (IP_MF | IP_OFFSET)) != 0;
	mf = (frag_off & IP_MF) != 0;
	first = (frag_off & IP_OFFSET) == 0;
	l4len = tot_len - ihl;

	if (is_frag && proto == IPPROTO_ICMP)
		/* ICMPv6 checksum needs the length of the whole datagram. */
		return DROP(CNT_EGRESS_DROP_FRAG_NO_CSUM);

	/* IPv4 options: drop source routes, strip the rest (RFC 7915 4.1). */
	optlen = ihl - IP4_HLEN;
	if (optlen) {
		if (ip4_has_source_route(skb, ETH_HLEN + IP4_HLEN, optlen))
			return DROP(CNT_EGRESS_DROP_SRCROUTE);
		if (bpf_skb_adjust_room(skb, -(__s32)optlen, BPF_ADJ_ROOM_NET,
					ROOM_FLAGS) < 0)
			return DROP(CNT_EGRESS_DROP_HELPER);
	}

	nh6 = proto == IPPROTO_ICMP ? IPPROTO_ICMPV6 : proto;

	/* Reshape the packet: 20-byte IPv4 header -> 40-byte IPv6 header,
	 * plus a Fragment header when the IPv4 packet is a fragment. */
	if (bpf_skb_change_proto(skb, bpf_htons(ETH_P_IPV6), 0) < 0)
		return DROP(CNT_EGRESS_DROP_HELPER);
	if (is_frag &&
	    bpf_skb_adjust_room(skb, FRAG_HLEN, BPF_ADJ_ROOM_NET, ROOM_FLAGS) < 0)
		return DROP(CNT_EGRESS_DROP_HELPER);

	*(__be32 *)&h6 = bpf_htonl(0x60000000 | ((__u32)tos << 20));
	h6.payload_len = bpf_htons(l4len + (is_frag ? FRAG_HLEN : 0));
	h6.nexthdr = is_frag ? IPPROTO_FRAGMENT : nh6;
	h6.hop_limit = ttl;
	prefix_copy(&h6.saddr, &POD_IP6);
	prefix_copy(&h6.daddr, &CLAT_PREFIX);
	h6.daddr.in6_u.u6_addr32[3] = daddr;
	if (bpf_skb_store_bytes(skb, ETH_HLEN, &h6, sizeof(h6), STORE_FLAGS) < 0)
		return DROP(CNT_EGRESS_DROP_HELPER);

	l4off = ETH_HLEN + IP6_HLEN;
	if (is_frag) {
		struct frag_hdr fh = {
			.nexthdr = nh6,
			.reserved = 0,
			.frag_off = bpf_htons(((frag_off & IP_OFFSET) << 3) | (mf ? 1 : 0)),
			.identification = bpf_htonl(bpf_ntohs(id)),
		};
		if (bpf_skb_store_bytes(skb, l4off, &fh, sizeof(fh), STORE_FLAGS) < 0)
			return DROP(CNT_EGRESS_DROP_HELPER);
		l4off += FRAG_HLEN;
	}

	{
		__be16 p = bpf_htons(ETH_P_IPV6);
		/* The MAC header is outside skb->csum coverage: no recompute. */
		if (bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_proto), &p,
					sizeof(p), 0) < 0)
			return DROP(CNT_EGRESS_DROP_HELPER);
	}

	if (!first)
		goto done;

	/* Pseudo-header delta: the addresses are the only fields that change
	 * between the IPv4 and the IPv6 pseudo-header for TCP and UDP. */
	addr4[0] = saddr;
	addr4[1] = daddr;
	diff = bpf_csum_diff(addr4, sizeof(addr4), (__be32 *)&h6.saddr,
			     2 * sizeof(struct in6_addr), 0);

	switch (proto) {
	case IPPROTO_TCP:
		if (bpf_l4_csum_replace(skb, l4off + 16, 0, diff,
					BPF_F_PSEUDO_HDR) < 0)
			return DROP(CNT_EGRESS_DROP_HELPER);
		break;
	case IPPROTO_UDP: {
		__be16 check;
		struct pseudo6 p6;

		if (bpf_skb_load_bytes(skb, l4off + 6, &check, sizeof(check)) < 0)
			return DROP(CNT_EGRESS_DROP_TRUNCATED);
		if (check != 0) {
			if (bpf_l4_csum_replace(skb, l4off + 6, 0, diff,
						BPF_F_PSEUDO_HDR |
							BPF_F_MARK_MANGLED_0) < 0)
				return DROP(CNT_EGRESS_DROP_HELPER);
			break;
		}
		/*
		 * A zero checksum field is either an IPv4 datagram sent without
		 * a checksum (SO_NO_CHECK) or, one time in 65536, a
		 * CHECKSUM_PARTIAL packet whose pseudo-header sum folds to zero.
		 * The program cannot see ip_summed, but it can recompute the
		 * IPv4 pseudo-header sum: if that folds to zero the field is
		 * (almost certainly) a partial checksum and the regular update
		 * applies. Otherwise the datagram really has no checksum, which
		 * IPv6 forbids, so compute one over the whole datagram.
		 */
		{
			__be32 p4[4] = { saddr, daddr, bpf_htonl(IPPROTO_UDP),
					 bpf_htonl(l4len) };
			if (csum_fold(bpf_csum_diff(NULL, 0, p4, sizeof(p4), 0)) == 0) {
				if (bpf_l4_csum_replace(skb, l4off + 6, 0, diff,
							BPF_F_PSEUDO_HDR |
								BPF_F_MARK_MANGLED_0 |
								BPF_F_MARK_ENFORCE) < 0)
					return DROP(CNT_EGRESS_DROP_HELPER);
				break;
			}
		}
		if (is_frag)
			return DROP(CNT_EGRESS_DROP_FRAG_NO_CSUM);
		prefix_copy(&p6.saddr, &h6.saddr);
		prefix_copy(&p6.daddr, &h6.daddr);
		p6.len = bpf_htonl(l4len);
		p6.nexthdr = bpf_htonl(IPPROTO_UDP);
		{
			__u16 full;
			__wsum seed = bpf_csum_diff(NULL, 0, (__be32 *)&p6,
						    sizeof(p6), 0);
			if (udp_full_csum(skb, l4off, l4len, seed, &full) < 0)
				return DROP(CNT_EGRESS_DROP_TOO_BIG);
			if (bpf_skb_store_bytes(skb, l4off + 6, &full, sizeof(full),
						STORE_FLAGS) < 0)
				return DROP(CNT_EGRESS_DROP_HELPER);
		}
		break;
	}
	case IPPROTO_ICMP: {
		struct pseudo6 p6;
		__u8 tc[2], t4, t6;
		__be32 oldw, neww;

		if (bpf_skb_load_bytes(skb, l4off, tc, sizeof(tc)) < 0)
			return DROP(CNT_EGRESS_DROP_TRUNCATED);
		t4 = tc[0];
		if (t4 == ICMP_ECHO)
			t6 = ICMPV6_ECHO_REQUEST;
		else if (t4 == ICMP_ECHOREPLY)
			t6 = ICMPV6_ECHO_REPLY;
		else
			/* Phase 1: no ICMPv4 error translation on egress. */
			return DROP(CNT_EGRESS_DROP_ICMP_UNSUPPORTED);

		/* ICMPv6 adds a pseudo-header that ICMPv4 does not have. */
		prefix_copy(&p6.saddr, &h6.saddr);
		prefix_copy(&p6.daddr, &h6.daddr);
		p6.len = bpf_htonl(l4len);
		p6.nexthdr = bpf_htonl(IPPROTO_ICMPV6);
		diff = bpf_csum_diff(NULL, 0, (__be32 *)&p6, sizeof(p6), 0);
		/* Type byte change, as a 32-bit word in packet byte order. */
		oldw = bpf_htonl((__u32)t4 << 24 | (__u32)tc[1] << 16);
		neww = bpf_htonl((__u32)t6 << 24 | (__u32)tc[1] << 16);
		diff = bpf_csum_diff(&oldw, sizeof(oldw), &neww, sizeof(neww), diff);
		if (bpf_skb_store_bytes(skb, l4off, &t6, sizeof(t6), STORE_FLAGS) < 0)
			return DROP(CNT_EGRESS_DROP_HELPER);
		if (bpf_l4_csum_replace(skb, l4off + 2, 0, diff, BPF_F_PSEUDO_HDR) < 0)
			return DROP(CNT_EGRESS_DROP_HELPER);
		break;
	}
	default:
		/* Other protocols carry over unchanged (SCTP has no
		 * pseudo-header in its CRC; the rest are exotic). */
		break;
	}

done:
	count(CNT_EGRESS_TRANSLATED);
	return TC_ACT_OK;
}

/*
 * ---------------------------------------------------------------------------
 * Ingress: IPv6 -> IPv4
 * ---------------------------------------------------------------------------
 */

struct icmp_map {
	__u8 type;
	__u8 code;
	bool ok;
};

/* RFC 7915 section 5.2, ICMPv6 error -> ICMPv4 error. */
static __always_inline struct icmp_map icmp6_to_icmp4(__u8 type, __u8 code,
						      __u32 pointer6, __u32 *pointer4)
{
	struct icmp_map m = { .ok = true };

	switch (type) {
	case ICMPV6_DEST_UNREACH:
		m.type = ICMP_DEST_UNREACH;
		switch (code) {
		case ICMPV6_NOROUTE:
		case ICMPV6_NOT_NEIGHBOUR:
		case ICMPV6_ADDR_UNREACH:
			m.code = ICMP_HOST_UNREACH;
			break;
		case ICMPV6_ADM_PROHIBITED:
		case ICMPV6_POLICY_FAIL:
		case ICMPV6_REJECT_ROUTE:
			m.code = ICMP_HOST_ANO;
			break;
		case ICMPV6_PORT_UNREACH:
			m.code = ICMP_PORT_UNREACH;
			break;
		default:
			m.code = ICMP_HOST_UNREACH;
		}
		break;
	case ICMPV6_PKT_TOOBIG:
		m.type = ICMP_DEST_UNREACH;
		m.code = ICMP_FRAG_NEEDED;
		break;
	case ICMPV6_TIME_EXCEED:
		m.type = ICMP_TIME_EXCEEDED;
		m.code = code; /* 0 hop limit, 1 reassembly */
		break;
	case ICMPV6_PARAMPROB:
		if (code == ICMPV6_UNK_NEXTHDR) {
			m.type = ICMP_DEST_UNREACH;
			m.code = ICMP_PROT_UNREACH;
			break;
		}
		if (code != ICMPV6_HDR_FIELD) {
			m.ok = false;
			break;
		}
		m.type = ICMP_PARAMETERPROB;
		m.code = 0;
		switch (pointer6) {
		case 0: *pointer4 = 0; break;   /* version / class -> version */
		case 4: *pointer4 = 2; break;   /* payload length -> total length */
		case 6: *pointer4 = 9; break;   /* next header -> protocol */
		case 7: *pointer4 = 8; break;   /* hop limit -> TTL */
		case 8: *pointer4 = 12; break;  /* source address */
		case 24: *pointer4 = 16; break; /* destination address */
		default: m.ok = false;
		}
		break;
	default:
		m.ok = false;
	}
	return m;
}

SEC("tc")
int clat_ingress(struct __sk_buff *skb)
{
	void *data, *data_end;
	struct ethhdr *eth;
	struct ipv6hdr *ip6;
	struct iphdr h4 = {};
	struct in6_addr saddr6, daddr6;
	__u32 l4off, payload_len;
	__u16 tot_len, id = 0, frag4 = IP_DF;
	__u8 tos, hop, nh, proto4;
	bool is_frag = false, first = true, src_mapped;
	__wsum diff;

	data = (void *)(long)skb->data;
	data_end = (void *)(long)skb->data_end;
	eth = data;
	if ((void *)(eth + 1) > data_end)
		return TC_ACT_OK;
	if (eth->h_proto != bpf_htons(ETH_P_IPV6))
		return TC_ACT_OK;

	if (!ensure_linear(skb, ETH_HLEN + IP6_HLEN + FRAG_HLEN))
		/* Shorter than 62 bytes: may still be a valid packet for the
		 * pod. Let it through, the stack will judge it. */
		return TC_ACT_OK;
	data = (void *)(long)skb->data;
	data_end = (void *)(long)skb->data_end;
	ip6 = data + ETH_HLEN;
	if ((void *)(ip6 + 1) > data_end)
		return TC_ACT_OK;
	if (ip6->version != 6)
		return TC_ACT_OK;

	saddr6 = ip6->saddr;
	daddr6 = ip6->daddr;
	if (!addr6_eq(&daddr6, &POD_IP6))
		return TC_ACT_OK;
	src_mapped = in_prefix(&saddr6);
	if (!src_mapped) {
		/* Not from the CLAT prefix. The only packets of interest are
		 * ICMPv6 errors from routers on the path that quote a CLAT
		 * flow (RFC 7915 5.2). Everything else is native IPv6. */
		struct ipv6hdr *in6;
		__u8 *icmp6;

		if (ip6->nexthdr != IPPROTO_ICMPV6)
			return TC_ACT_OK;
		if (!ensure_linear(skb, ETH_HLEN + IP6_HLEN + 8 + IP6_HLEN))
			return TC_ACT_OK;
		data = (void *)(long)skb->data;
		data_end = (void *)(long)skb->data_end;
		ip6 = data + ETH_HLEN;
		icmp6 = (void *)(ip6 + 1);
		in6 = (void *)(icmp6 + 8);
		if ((void *)(in6 + 1) > data_end)
			return TC_ACT_OK;
		if (icmp6[0] < ICMPV6_DEST_UNREACH || icmp6[0] > ICMPV6_PARAMPROB)
			return TC_ACT_OK;
		if (in6->version != 6 || !addr6_eq(&in6->saddr, &POD_IP6) ||
		    !in_prefix(&in6->daddr))
			return TC_ACT_OK;
	}

	/* From here on the packet is CLAT return traffic. */
	tos = (__u8)(bpf_ntohl(*(__be32 *)ip6) >> 20);
	hop = ip6->hop_limit;
	nh = ip6->nexthdr;
	payload_len = bpf_ntohs(ip6->payload_len);

	if (nh == IPPROTO_FRAGMENT) {
		struct frag_hdr *fh = (void *)(ip6 + 1);
		__u16 fo;

		if ((void *)(fh + 1) > data_end)
			return DROP(CNT_INGRESS_DROP_TRUNCATED);
		if (payload_len < FRAG_HLEN)
			return DROP(CNT_INGRESS_DROP_TRUNCATED);
		nh = fh->nexthdr;
		fo = bpf_ntohs(fh->frag_off);
		id = (__u16)bpf_ntohl(fh->identification);
		frag4 = (fo >> 3) | ((fo & 1) ? IP_MF : 0);
		first = (fo >> 3) == 0;
		is_frag = true;
		payload_len -= FRAG_HLEN;
	}
	if (is_ext_hdr(nh))
		return DROP(CNT_INGRESS_DROP_EXTHDR);

	proto4 = nh == IPPROTO_ICMPV6 ? IPPROTO_ICMP : nh;
	if (nh == IPPROTO_ICMPV6 && is_frag)
		/* The ICMPv4 checksum needs the length of the whole datagram
		 * to strip the pseudo-header. Not knowable statelessly. */
		return DROP(CNT_INGRESS_DROP_FRAG_ICMP);

	/* Reshape: drop the Fragment header, shrink 40 -> 20. */
	if (is_frag &&
	    bpf_skb_adjust_room(skb, -(__s32)FRAG_HLEN, BPF_ADJ_ROOM_NET,
				ROOM_FLAGS) < 0)
		return DROP(CNT_INGRESS_DROP_HELPER);
	if (bpf_skb_change_proto(skb, bpf_htons(ETH_P_IP), 0) < 0)
		return DROP(CNT_INGRESS_DROP_HELPER);

	tot_len = payload_len + IP4_HLEN;
	h4.version = 4;
	h4.ihl = 5;
	h4.tos = tos;
	h4.tot_len = bpf_htons(tot_len);
	h4.id = bpf_htons(id);
	h4.frag_off = bpf_htons(frag4);
	h4.ttl = hop;
	h4.protocol = proto4;
	h4.check = 0;
	h4.saddr = src_mapped ? saddr6.in6_u.u6_addr32[3] : ERR_IP4;
	h4.daddr = POD_IP4;
	h4.check = csum_fold(bpf_csum_diff(NULL, 0, (__be32 *)&h4, sizeof(h4), 0));
	if (bpf_skb_store_bytes(skb, ETH_HLEN, &h4, sizeof(h4), STORE_FLAGS) < 0)
		return DROP(CNT_INGRESS_DROP_HELPER);
	{
		__be16 p = bpf_htons(ETH_P_IP);
		if (bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_proto), &p,
					sizeof(p), 0) < 0)
			return DROP(CNT_INGRESS_DROP_HELPER);
	}
	l4off = ETH_HLEN + IP4_HLEN;

	if (!first)
		goto done;

	{
		__be32 addr4[2] = { h4.saddr, h4.daddr };
		struct in6_addr addr6[2];
		prefix_copy(&addr6[0], &saddr6);
		prefix_copy(&addr6[1], &daddr6);
		diff = bpf_csum_diff((__be32 *)addr6, sizeof(addr6), addr4,
				     sizeof(addr4), 0);
	}

	switch (nh) {
	case IPPROTO_TCP:
		if (bpf_l4_csum_replace(skb, l4off + 16, 0, diff,
					BPF_F_PSEUDO_HDR) < 0)
			return DROP(CNT_INGRESS_DROP_HELPER);
		break;
	case IPPROTO_UDP: {
		__be16 check;

		if (bpf_skb_load_bytes(skb, l4off + 6, &check, sizeof(check)) < 0)
			return DROP(CNT_INGRESS_DROP_TRUNCATED);
		if (check == 0)
			/* Illegal in IPv6 (RFC 7915 5.5). */
			return DROP(CNT_INGRESS_DROP_UDP_ZERO_CSUM);
		if (bpf_l4_csum_replace(skb, l4off + 6, 0, diff,
					BPF_F_PSEUDO_HDR | BPF_F_MARK_MANGLED_0) < 0)
			return DROP(CNT_INGRESS_DROP_HELPER);
		break;
	}
	case IPPROTO_ICMPV6: {
		struct pseudo6 p6;
		__u8 hdr[8];
		__u8 t6, code;

		if (bpf_skb_load_bytes(skb, l4off, hdr, sizeof(hdr)) < 0)
			return DROP(CNT_INGRESS_DROP_TRUNCATED);
		t6 = hdr[0];
		code = hdr[1];

		/* Remove the ICMPv6 pseudo-header. */
		prefix_copy(&p6.saddr, &saddr6);
		prefix_copy(&p6.daddr, &daddr6);
		p6.len = bpf_htonl(payload_len);
		p6.nexthdr = bpf_htonl(IPPROTO_ICMPV6);
		diff = bpf_csum_diff((__be32 *)&p6, sizeof(p6), NULL, 0, 0);

		if (t6 == ICMPV6_ECHO_REPLY || t6 == ICMPV6_ECHO_REQUEST) {
			__u8 t4 = t6 == ICMPV6_ECHO_REPLY ? ICMP_ECHOREPLY : ICMP_ECHO;
			__be32 oldw = bpf_htonl((__u32)t6 << 24 | (__u32)code << 16);
			__be32 neww = bpf_htonl((__u32)t4 << 24 | (__u32)code << 16);

			diff = bpf_csum_diff(&oldw, sizeof(oldw), &neww, sizeof(neww), diff);
			if (bpf_skb_store_bytes(skb, l4off, &t4, sizeof(t4), STORE_FLAGS) < 0)
				return DROP(CNT_INGRESS_DROP_HELPER);
			if (bpf_l4_csum_replace(skb, l4off + 2, 0, diff, BPF_F_PSEUDO_HDR) < 0)
				return DROP(CNT_INGRESS_DROP_HELPER);
			break;
		}

		/* ICMPv6 error: translate the header and the embedded packet. */
		{
			struct icmp_map m;
			__u32 pointer4 = 0;
			struct {
				__u8 icmp6[8];
				struct ipv6hdr in6;
				struct frag_hdr infh;
			} old = {};
			struct {
				struct icmphdr icmp4;
				struct iphdr in4;
			} new = {};
			bool in_frag = false;
			__u32 in_l4off = l4off + 8 + IP6_HLEN;
			__u16 in_id = 0, in_frag4 = IP_DF;
			__u8 in_nh;
			__wsum d;

			m = icmp6_to_icmp4(t6, code, bpf_ntohl(*(__be32 *)&hdr[4]),
					   &pointer4);
			if (!m.ok)
				return DROP(CNT_INGRESS_DROP_ICMP_UNSUPPORTED);

			__builtin_memcpy(old.icmp6, hdr, sizeof(old.icmp6));
			if (bpf_skb_load_bytes(skb, l4off + 8, &old.in6, IP6_HLEN) < 0)
				return DROP(CNT_INGRESS_DROP_ICMP_INNER);
			if (old.in6.version != 6 || !addr6_eq(&old.in6.saddr, &POD_IP6) ||
			    !in_prefix(&old.in6.daddr))
				return DROP(CNT_INGRESS_DROP_ICMP_INNER);
			in_nh = old.in6.nexthdr;
			if (in_nh == IPPROTO_FRAGMENT) {
				__u16 fo;
				if (bpf_skb_load_bytes(skb, in_l4off, &old.infh, FRAG_HLEN) < 0)
					return DROP(CNT_INGRESS_DROP_ICMP_INNER);
				in_nh = old.infh.nexthdr;
				fo = bpf_ntohs(old.infh.frag_off);
				in_id = (__u16)bpf_ntohl(old.infh.identification);
				in_frag4 = (fo >> 3) | ((fo & 1) ? IP_MF : 0);
				in_frag = true;
				in_l4off += FRAG_HLEN;
			}
			if (is_ext_hdr(in_nh))
				return DROP(CNT_INGRESS_DROP_ICMP_INNER);

			/* New ICMPv4 header. */
			new.icmp4.type = m.type;
			new.icmp4.code = m.code;
			new.icmp4.checksum = 0;
			if (t6 == ICMPV6_PKT_TOOBIG) {
				__u32 mtu = bpf_ntohl(*(__be32 *)&hdr[4]);
				__u32 hdrdiff = IP6_HLEN - IP4_HLEN +
						(in_frag ? FRAG_HLEN : 0);
				if (mtu > 0xffff)
					mtu = 0xffff;
				mtu = mtu > hdrdiff + 68 ? mtu - hdrdiff : 68;
				new.icmp4.un.frag.__unused = 0;
				new.icmp4.un.frag.mtu = bpf_htons((__u16)mtu);
			} else if (m.type == ICMP_PARAMETERPROB) {
				new.icmp4.un.gateway = bpf_htonl(pointer4 << 24);
			} else {
				new.icmp4.un.gateway = 0;
			}

			/* New embedded IPv4 header. */
			new.in4.version = 4;
			new.in4.ihl = 5;
			new.in4.tos = (__u8)(bpf_ntohl(*(__be32 *)&old.in6) >> 20);
			new.in4.tot_len = bpf_htons(bpf_ntohs(old.in6.payload_len) + IP4_HLEN -
						    (in_frag ? FRAG_HLEN : 0));
			new.in4.id = bpf_htons(in_id);
			new.in4.frag_off = bpf_htons(in_frag4);
			new.in4.ttl = old.in6.hop_limit;
			new.in4.protocol = in_nh == IPPROTO_ICMPV6 ? IPPROTO_ICMP : in_nh;
			new.in4.saddr = POD_IP4;
			new.in4.daddr = old.in6.daddr.in6_u.u6_addr32[3];
			new.in4.check = csum_fold(bpf_csum_diff(NULL, 0, (__be32 *)&new.in4,
								sizeof(new.in4), 0));

			/* ICMPv4 checksum: old bytes (and the pseudo-header, already in
			 * diff) out, new bytes in. */
			if (in_frag)
				d = bpf_csum_diff((__be32 *)&old, sizeof(old), (__be32 *)&new,
						  sizeof(new), diff);
			else
				d = bpf_csum_diff((__be32 *)&old, sizeof(old) - FRAG_HLEN,
						  (__be32 *)&new, sizeof(new), diff);

			/* Shrink the embedded header in place: removes the ICMPv6
			 * header and the first part of the embedded IPv6 header. */
			if (bpf_skb_adjust_room(skb,
						in_frag ? -(__s32)(sizeof(old) - sizeof(new))
							: -(__s32)(sizeof(old) - FRAG_HLEN - sizeof(new)),
						BPF_ADJ_ROOM_NET, ROOM_FLAGS) < 0)
				return DROP(CNT_INGRESS_DROP_HELPER);
			if (bpf_skb_store_bytes(skb, l4off, &new, sizeof(new), STORE_FLAGS) < 0)
				return DROP(CNT_INGRESS_DROP_HELPER);

			/* The outer IPv4 header was written for the unshrunk packet:
			 * fix its total length and header checksum. */
			h4.tot_len = bpf_htons(tot_len - (in_frag ? sizeof(old) - sizeof(new)
								  : sizeof(old) - FRAG_HLEN - sizeof(new)));
			h4.check = 0;
			h4.check = csum_fold(bpf_csum_diff(NULL, 0, (__be32 *)&h4, sizeof(h4), 0));
			if (bpf_skb_store_bytes(skb, ETH_HLEN, &h4, sizeof(h4), STORE_FLAGS) < 0)
				return DROP(CNT_INGRESS_DROP_HELPER);

			/* Embedded transport checksum, when present. It is not
			 * verified by receivers, but keep it right where cheap. */
			{
				__u32 l4 = l4off + sizeof(new);
				__u32 coff = 0;
				__be32 in4[2] = { new.in4.saddr, new.in4.daddr };
				struct in6_addr in6[2];
				__wsum id6;
				__be16 oc, nc;

				prefix_copy(&in6[0], &old.in6.saddr);
				prefix_copy(&in6[1], &old.in6.daddr);
				id6 = bpf_csum_diff((__be32 *)in6, sizeof(in6), in4, sizeof(in4), 0);

				if (in_nh == IPPROTO_UDP)
					coff = 6;
				else if (in_nh == IPPROTO_TCP)
					coff = 16;
				if (in_nh == IPPROTO_ICMPV6 && !in_frag) {
					/* Embedded echo: type 128/129 -> 8/0, and its
					 * checksum loses the pseudo-header. Linux ping
					 * sockets ignore errors whose quoted type is not
					 * ICMP_ECHO. Skip when the quoted packet was a
					 * fragment: its checksum is not computable. */
					struct pseudo6 ip6;
					__u8 it[2], nt;
					__be32 ow, nw;
					__wsum idiff;

					if (bpf_skb_load_bytes(skb, l4, it, sizeof(it)) < 0)
						return DROP(CNT_INGRESS_DROP_ICMP_INNER);
					if (it[0] == ICMPV6_ECHO_REQUEST || it[0] == ICMPV6_ECHO_REPLY) {
						nt = it[0] == ICMPV6_ECHO_REQUEST ? ICMP_ECHO : ICMP_ECHOREPLY;
						prefix_copy(&ip6.saddr, &old.in6.saddr);
						prefix_copy(&ip6.daddr, &old.in6.daddr);
						ip6.len = bpf_htonl(bpf_ntohs(old.in6.payload_len));
						ip6.nexthdr = bpf_htonl(IPPROTO_ICMPV6);
						idiff = bpf_csum_diff((__be32 *)&ip6, sizeof(ip6), NULL, 0, 0);
						ow = bpf_htonl((__u32)it[0] << 24 | (__u32)it[1] << 16);
						nw = bpf_htonl((__u32)nt << 24 | (__u32)it[1] << 16);
						idiff = bpf_csum_diff(&ow, sizeof(ow), &nw, sizeof(nw), idiff);
						if (bpf_skb_load_bytes(skb, l4 + 2, &oc, sizeof(oc)) < 0)
							return DROP(CNT_INGRESS_DROP_ICMP_INNER);
						nc = csum_fold((__wsum)idiff + (__wsum)(__u16)~oc);
						if (bpf_skb_store_bytes(skb, l4, &nt, sizeof(nt), STORE_FLAGS) < 0 ||
						    bpf_skb_store_bytes(skb, l4 + 2, &nc, sizeof(nc), STORE_FLAGS) < 0)
							return DROP(CNT_INGRESS_DROP_HELPER);
						/* Both changes are in-packet: feed them to the
						 * outer checksum update too. */
						d = bpf_csum_diff(&ow, sizeof(ow), &nw, sizeof(nw), d);
						ow = word16(oc);
						nw = word16(nc);
						d = bpf_csum_diff(&ow, sizeof(ow), &nw, sizeof(nw), d);
					}
				}
				if (coff && (in_frag4 & IP_OFFSET) == 0 &&
				    bpf_skb_load_bytes(skb, l4 + coff, &oc, sizeof(oc)) == 0 &&
				    oc != 0) {
					__be32 ow, nw;
					/* C' = ~(~C + (P4 - P6)), csum_fold complements. */
					nc = csum_fold((__wsum)id6 + (__wsum)(__u16)~oc);
					if (bpf_skb_store_bytes(skb, l4 + coff, &nc, sizeof(nc),
								STORE_FLAGS) < 0)
						return DROP(CNT_INGRESS_DROP_HELPER);
					ow = word16(oc);
					nw = word16(nc);
					d = bpf_csum_diff(&ow, sizeof(ow), &nw, sizeof(nw), d);
				}
			}

			if (bpf_l4_csum_replace(skb, l4off + 2, 0, d, BPF_F_PSEUDO_HDR) < 0)
				return DROP(CNT_INGRESS_DROP_HELPER);
		}
		break;
	}
	default:
		break;
	}

done:
	count(CNT_INGRESS_TRANSLATED);
	return TC_ACT_OK;
}
