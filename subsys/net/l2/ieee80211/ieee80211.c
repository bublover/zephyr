

#define LOG_MODULE_NAME net_ieee80211
#define NET_LOG_LEVEL CONFIG_NET_L2_IEEE80211_LOG_LEVEL

#include <net/net_core.h>
#include <net/net_l2.h>
#include <net/net_if.h>
#include <net/ieee80211.h>
#include <net/ethernet.h>

#include "arp.h"
#include "net_private.h"

static const struct net_eth_addr broadcast_ieee80211_addr = {
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff } };

const struct net_eth_addr *net_ieee80211_broadcast_addr(void)
{
	return &broadcast_ieee80211_addr;
}

#define print_ll_addrs(pkt, type, len, src, dst) \
	do { \
		if (NET_LOG_LEVEL >= LOG_LEVEL_DBG) { \
			char out[sizeof("xx:xx:xx:xx:xx:xx")]; \
			\
			snprintk(out, sizeof(out), "%s", \
					net_sprint_ll_addr((src)->addr, \
						sizeof(struct net_eth_addr))); \
			\
			NET_DBG("iface %p src %s dst %s type 0x%x len %zu", \
					net_pkt_iface(pkt), log_strdup(out), \
					log_strdup( \
						net_sprint_ll_addr( \
							(dst)->addr, \
						sizeof(struct net_eth_addr))), \
					type, (size_t)len);	\
		} \
	} while (0)

static inline void ieee80211_update_length(struct net_if *iface,
					  struct net_pkt *pkt)
{
	u16_t len;

	/* Let's check IP payload's length. If it's smaller than 46 bytes,
	 * i.e. smaller than minimal Ethernet frame size minus ethernet
	 * header size,then Ethernet has padded so it fits in the minimal
	 * frame size of 60 bytes. In that case, we need to get rid of it.
	 */

	if (net_pkt_family(pkt) == AF_INET) {
		len = ntohs(NET_IPV4_HDR(pkt)->len);
	} else {
		len = ntohs(NET_IPV6_HDR(pkt)->len) + NET_IPV6H_LEN;
	}

	if (len < NET_ETH_MINIMAL_FRAME_SIZE - sizeof(struct net_eth_hdr)) {
		struct net_buf *frag;

		for (frag = pkt->frags; frag; frag = frag->frags) {
			if (frag->len < len) {
				len -= frag->len;
			} else {
				frag->len = len;
				len = 0;
			}
		}
	}
}

static enum net_verdict ieee80211_recv(struct net_if *iface,
					struct net_pkt *pkt)
{
	struct net_eth_hdr *hdr = NET_ETH_HDR(pkt);
	struct net_linkaddr *lladdr;
	sa_family_t family;
	u16_t type = ntohs(hdr->type);
	u8_t hdr_len = sizeof(struct net_eth_hdr);

	switch (type) {
	case NET_ETH_PTYPE_IP:
	case NET_ETH_PTYPE_ARP:
		net_pkt_set_family(pkt, AF_INET);
		family = AF_INET;
		break;
	case NET_ETH_PTYPE_IPV6:
		net_pkt_set_family(pkt, AF_INET6);
		family = AF_INET6;
		break;
	default:
		NET_DBG("Unknown hdr type 0x%04x iface %p", type, iface);
		return NET_DROP;
	}

	/* Set the pointers to ll src and dst addresses */
	lladdr = net_pkt_lladdr_src(pkt);
	lladdr->addr = ((struct net_eth_hdr *)net_pkt_ll(pkt))->src.addr;
	lladdr->len = sizeof(struct net_eth_addr);
	lladdr->type = NET_LINK_IEEE80211;

	lladdr = net_pkt_lladdr_dst(pkt);
	lladdr->addr = ((struct net_eth_hdr *)net_pkt_ll(pkt))->dst.addr;
	lladdr->len = sizeof(struct net_eth_addr);
	lladdr->type = NET_LINK_IEEE80211;

	if (!net_eth_is_addr_broadcast((struct net_eth_addr *)lladdr->addr)
			&& !net_linkaddr_cmp(
				net_if_get_link_addr(iface),
				lladdr)) {
		NET_DBG("Dropping frame, not for me [%s]",
			log_strdup(net_sprint_ll_addr(
					   net_if_get_link_addr(iface)->addr,
					   sizeof(struct net_eth_addr))));

		return NET_DROP;
	}

	net_pkt_set_ll_reserve(pkt, hdr_len);
	net_buf_pull(pkt->frags, net_pkt_ll_reserve(pkt));

#ifdef CONFIG_NET_ARP
	if (family == AF_INET && type == NET_ETH_PTYPE_ARP) {
		NET_DBG("ARP packet from %s received",
			log_strdup(net_sprint_ll_addr(
					   (u8_t *)hdr->src.addr,
					   sizeof(struct net_eth_addr))));

#ifdef CONFIG_NET_IPV4_AUTO
		if (net_ipv4_autoconf_input(iface, pkt) == NET_DROP) {
			return NET_DROP;
		}
#endif
		return net_arp_input(pkt);
	}
#endif

	ieee80211_update_length(iface, pkt);

	return NET_CONTINUE;
}

struct net_eth_hdr *net_ieee80211_fill_header(struct ieee80211_context *ctx,
					struct net_pkt *pkt,
					u32_t ptype,
					u8_t *src,
					u8_t *dst)
{
	struct net_eth_hdr *hdr;
	struct net_buf *frag = pkt->frags;

	NET_ASSERT(net_buf_headroom(frag) >= sizeof(struct net_eth_hdr));

	hdr = (struct net_eth_hdr *)(frag->data - net_pkt_ll_reserve(pkt));

	if (dst && ((u8_t *)&hdr->dst != dst)) {
		memcpy(&hdr->dst, dst, sizeof(struct net_eth_addr));
	}

	if (src && ((u8_t *)&hdr->src != src)) {
		memcpy(&hdr->src, src, sizeof(struct net_eth_addr));
	}

	hdr->type = ptype;

	print_ll_addrs(pkt, ntohs(hdr->type), frag->len, &hdr->src, &hdr->dst);

	return hdr;
}

#if defined(CONFIG_NET_IPV4_AUTO)
static inline bool is_ipv4_auto_arp_msg(struct net_pkt *pkt)
{
	return net_pkt_ipv4_auto(pkt);
}
#else
#define is_ipv4_auto_arp_msg(...) false
#endif

static inline bool check_if_dst_is_broadcast_or_mcast(struct net_if *iface,
						      struct net_pkt *pkt)
{
	struct net_eth_hdr *hdr = NET_ETH_HDR(pkt);

	if (net_ipv4_is_addr_bcast(iface, &NET_IPV4_HDR(pkt)->dst)) {
		/* Broadcast address */
		net_pkt_lladdr_dst(pkt)->addr =
			(u8_t *)broadcast_ieee80211_addr.addr;
		net_pkt_lladdr_dst(pkt)->len = sizeof(struct net_eth_addr);
		net_pkt_lladdr_src(pkt)->addr =
			net_if_get_link_addr(iface)->addr;
		net_pkt_lladdr_src(pkt)->len = sizeof(struct net_eth_addr);

		return true;
	} else if (NET_IPV4_HDR(pkt)->dst.s4_addr[0] == 224) {
		/* Multicast address */
		hdr->dst.addr[0] = 0x01;
		hdr->dst.addr[1] = 0x00;
		hdr->dst.addr[2] = 0x5e;
		hdr->dst.addr[3] = NET_IPV4_HDR(pkt)->dst.s4_addr[1];
		hdr->dst.addr[4] = NET_IPV4_HDR(pkt)->dst.s4_addr[2];
		hdr->dst.addr[5] = NET_IPV4_HDR(pkt)->dst.s4_addr[3];

		hdr->dst.addr[3] = hdr->dst.addr[3] & 0x7f;

		net_pkt_lladdr_dst(pkt)->len = sizeof(struct net_eth_addr);
		net_pkt_lladdr_src(pkt)->addr =
			net_if_get_link_addr(iface)->addr;
		net_pkt_lladdr_src(pkt)->len = sizeof(struct net_eth_addr);

		return true;
	}

	return false;
}

static enum net_verdict ieee80211_send(struct net_if *iface,
					struct net_pkt *pkt)
{
	struct ieee80211_context *ctx = net_if_l2_data(iface);
	u16_t ptype;

#ifdef CONFIG_NET_ARP
	if (net_pkt_family(pkt) == AF_INET) {
		struct net_pkt *arp_pkt;

		if (check_if_dst_is_broadcast_or_mcast(iface, pkt)) {
			if (!net_pkt_lladdr_dst(pkt)->addr) {
				struct net_eth_addr *dst;

				dst = &NET_ETH_HDR(pkt)->dst;
				net_pkt_lladdr_dst(pkt)->addr =
					(u8_t *)dst->addr;
			}

			goto setup_hdr;
		}

		/* Trying to send ARP message so no need to setup it twice */
		if (!is_ipv4_auto_arp_msg(pkt)) {
			arp_pkt = net_arp_prepare(pkt, &NET_IPV4_HDR(pkt)->dst,
						  NULL);
			if (!arp_pkt) {
				return NET_DROP;
			}

			if (pkt != arp_pkt) {
				NET_DBG("Sending arp pkt %p (orig %p) to "
					"iface %p",
					arp_pkt, pkt, iface);

				/* Either pkt went to ARP pending queue or
				 * there was no space in the queue anymore.
				 */
				net_pkt_unref(pkt);

				pkt = arp_pkt;
			} else {
				NET_DBG("Found ARP entry, sending pkt %p to "
					"iface %p",
					pkt, iface);
			}
		}

		net_pkt_lladdr_src(pkt)->addr = (u8_t *)&NET_ETH_HDR(pkt)->src;
		net_pkt_lladdr_src(pkt)->len = sizeof(struct net_eth_addr);
		net_pkt_lladdr_dst(pkt)->addr = (u8_t *)&NET_ETH_HDR(pkt)->dst;
		net_pkt_lladdr_dst(pkt)->len = sizeof(struct net_eth_addr);

		/* For ARP message, we do not touch the packet further but will
		 * send it as it is because the arp.c has prepared the packet
		 * already.
		 */
		ptype = htons(NET_ETH_PTYPE_ARP);

		goto send_frame;
	}
#else
	NET_DBG("Sending pkt %p to iface %p", pkt, iface);
#endif

	/* If the src ll address is multicast or broadcast, then
	 * what probably happened is that the RX buffer is used
	 * for sending data back to recipient. We must
	 * substitute the src address using the real ll address.
	 */
	if (net_eth_is_addr_broadcast((struct net_eth_addr *)
					net_pkt_lladdr_src(pkt)->addr) ||
	    net_eth_is_addr_multicast((struct net_eth_addr *)
					net_pkt_lladdr_src(pkt)->addr)) {
		net_pkt_lladdr_src(pkt)->addr = net_pkt_lladdr_if(pkt)->addr;
		net_pkt_lladdr_src(pkt)->len = net_pkt_lladdr_if(pkt)->len;
	}

	/* If the destination address is not set, then use broadcast
	 * or multicast address.
	 */
	if (!net_pkt_lladdr_dst(pkt)->addr) {
#if defined(CONFIG_NET_IPV6)
		if (net_pkt_family(pkt) == AF_INET6 &&
		    net_ipv6_is_addr_mcast(&NET_IPV6_HDR(pkt)->dst)) {
			struct net_eth_addr *dst = &NET_ETH_HDR(pkt)->dst;

			memcpy(dst, (u8_t *)multicast_eth_addr.addr,
			       sizeof(struct net_eth_addr) - 4);
			memcpy((u8_t *)dst + 2,
			       (u8_t *)(&NET_IPV6_HDR(pkt)->dst) + 12,
				sizeof(struct net_eth_addr) - 2);

			net_pkt_lladdr_dst(pkt)->addr = (u8_t *)dst->addr;
		} else
#endif
		{
			net_pkt_lladdr_dst(pkt)->addr =
				(u8_t *)broadcast_ieee80211_addr.addr;
		}

		net_pkt_lladdr_dst(pkt)->len = sizeof(struct net_eth_addr);

		NET_DBG("Destination address was not set, using %s",
			log_strdup(net_sprint_ll_addr(
					   net_pkt_lladdr_dst(pkt)->addr,
					   net_pkt_lladdr_dst(pkt)->len)));
	}

setup_hdr:
	__unused;

	if (net_pkt_family(pkt) == AF_INET) {
		ptype = htons(NET_ETH_PTYPE_IP);
	} else {
		ptype = htons(NET_ETH_PTYPE_IPV6);
	}

send_frame:

	/* Then set the ethernet header. This is not done for ARP as arp.c
	 * has already prepared the message to be sent.
	 */
	if (ptype != htons(NET_ETH_PTYPE_ARP)) {
		net_ieee80211_fill_header(ctx, pkt, ptype,
				    net_pkt_lladdr_src(pkt)->addr,
				    net_pkt_lladdr_dst(pkt)->addr);
	}

	net_if_queue_tx(iface, pkt);

	return NET_OK;
}

static u16_t ieee80211_reserve(struct net_if *iface, void *data)
{
	NET_DBG("reserve %d bytes", sizeof(struct net_eth_hdr));

	return sizeof(struct net_eth_hdr);
}

static int ieee80211_enable(struct net_if *iface, bool state)
{
	return 0;
}

enum net_l2_flags ieee80211_flags(struct net_if *iface)
{
	struct ieee80211_context *ctx = net_if_l2_data(iface);

	return ctx->ieee80211_l2_flags;
}






NET_L2_INIT(IEEE80211_L2,
	    ieee80211_recv, ieee80211_send,
	    ieee80211_reserve, ieee80211_enable, ieee80211_flags);

void ieee80211_init(struct net_if *iface)
{
	struct ieee80211_context *ctx = net_if_l2_data(iface);

	ctx->ieee80211_l2_flags = NET_L2_MULTICAST;

	net_arp_init();
}
