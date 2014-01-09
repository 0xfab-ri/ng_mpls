#include "ng_mpls.h"
#include <netinet/if_ether.h>

/* ether_type of ether_header structure */
#define ETHERTYPE_MPLS_UNICAST      0x4788  /* frame is carrying an MPLS unicast packet */
#define ETHERTYPE_MPLS_MULTICAST    0x4888  /* frame is carrying an MPLS multicast packet */

#define ETHER_MPLS_ENCAP_LEN	32

/* for 5.4 */
#ifndef IFP2ENADDR
#define IFP2ENADDR(ifp) (((struct arpcom *)(ifp))->ac_enaddr)
#endif


/* remove label */
static void remove_label(struct mbuf *m)
{
	bcopy(mtod(m, caddr_t), mtod(m, caddr_t) + ETHER_MPLS_ENCAP_LEN, ETHER_HDR_LEN);
	m_adj(m, ETHER_MPLS_ENCAP_LEN);
}


/*
============
forward: forward ethernet frame m to entry->nextHop via entry->iface
============
*/
static int mpls_ether_forward(item_p item, interface_p interface, struct in_addr nexthop, struct mbuf *m, struct mbuf *copy)
{
	int error;
	unsigned char mac[ETHER_ADDR_LEN];
	struct ether_header *eh;
	struct sockaddr_in sin;

	if(!interface) {
		printf("mpls_ether_forward: no outgoing interface specified\n");
		return 0;
	}

	/* get ethernet header */
	eh = mtod(m, struct ether_header *);

	/* arp lookup destination MAC */
	sin.sin_family = AF_INET;
	sin.sin_addr = nexthop;
	sin.sin_port = 0;

	error = arpresolve(interface->ifnet, NULL, copy, (struct sockaddr *)&sin, mac);
	if(error == 0) {
		/* change ethernet header */
		bcopy(mac, eh->ether_dhost, ETHER_ADDR_LEN);
		bcopy(IFP2ENADDR(interface->ifnet), eh->ether_shost, ETHER_ADDR_LEN);

		/* free packet's copy */
		m_free(copy);

		/* forward this packet */
#ifdef _DEBUG
		printf("forward\n");
#endif
		NG_FWD_NEW_DATA(error, item, interface->lower, m);

		return 0;
	}

	/* free this item, it's no longer needed or it will be reinjected when arp reply arrives */
	NG_FREE_ITEM(item);

	return 0;
}


/*
============
processLowerEthernet
============
*/
int mpls_ether_lower(const priv_p priv, interface_p interface, item_p item, struct mbuf *m)
{
	int error = 0;
	uint32_t label, *label_stack;
	uint8_t exp, s, ttl;
	size_t len, len_ext;
	struct ether_header *eh;
	mpls_lib_entry_p entry, transport_entry;
	struct mbuf *copy, *mbuf_ip;
	struct ip *ip;

	if(m->m_len < sizeof(struct ether_header) && (m = m_pullup(m, sizeof(struct ether_header))) == NULL) {
		NG_FREE_ITEM(item);
		return (EINVAL);
	}

	eh = mtod(m, struct ether_header *);

	if(eh->ether_type == htons(ETHERTYPE_MPLS)) {
		/* this is an mpls packet */

		/* get top label */
		len = sizeof(struct ether_header) + ETHER_MPLS_ENCAP_LEN;
		if(m->m_len < len && (m = m_pullup(m, len)) == NULL) {
			NG_FREE_ITEM(item);
			return (EINVAL);
		}
		eh = mtod(m, struct ether_header *);
		getLabel(eh + 1, &label, &exp, &s, &ttl);

#ifdef _DEBUG
		printf("lower: mpls top label [%u %u %u %u]\n.", label, exp, s, ttl);
#endif

		/* drop dead packets */
		if(ttl == 0) {
			NG_FREE_ITEM(item);
			return 0;
		}
			
		/* decrement time-to-live value */
		ttl--;
				
		/* ILM lookup */
		entry = mpls_get_entry_by_label(label);
		if(!entry) {
			printf("Could not find an ILM entry for label %d.\n", label);
			NG_FREE_ITEM(item);
			return 0;
		}

		if(!entry->interface || !entry->interface->lower) {
			/* entry without outgoing interface, should we send it for upper layer processing? */
			if(entry->entry.type == LIB_IN && mpls_should_pop_label(entry->entry.remote)) {
				/* pop label and set ether_type to ip if it's the last label */
				if(s) {
					eh->ether_type = htons(ETHERTYPE_IP);
				}

				/* remove label */
				remove_label(m);

				/* recursively process the rest of the stack or forward to the upper hook */
				return mpls_ether_lower(priv, interface, item, m);
			}

			/* discard bad packet */
			NG_FREE_ITEM(item);
			return 0;
		}

		if(entry->entry.type == LIB_NORMAL) {
			/* simple switching */

			/* label swapping */
			if(mpls_should_pop_label(entry->entry.remote)) {
				/* the packet should be sent unlabelled so pop the label and set ether_type to ip if it's the last label */
				if(s) {
					eh->ether_type = htons(ETHERTYPE_IP);
				} else {
					/* TODO: Does this break stack logic? discard bad packet */
					NG_FREE_ITEM(item);
					return 0;
				}

				/* remove label */
				remove_label(m);
			} else {
				/* swap label */
				label = entry->entry.remote;
				setLabel(eh + 1, label, exp, s, ttl);
			}

			/* copy packet's mbuf for reinjecting by arp */
			copy = m_dup(m, M_DONTWAIT);
			if(copy == NULL) {
				return (ENOMEM);
			}

			/* forward this packet */
			return mpls_ether_forward(item, entry->interface, entry->entry.nexthop, m, copy);

		} else if(entry->entry.type == LIB_L2VPN) {
			/* L2VPN switching */

			/* VC label must be at the bottom of the stack */
			if(!s) {
				/* TODO: Does this break stack logic? */
				NG_FREE_ITEM(item);
				return 0;
			}

			/* remove ehternet header and label */
			m_adj(m, ETHER_HDR_LEN + ETHER_MPLS_ENCAP_LEN);

			/* forward frame for upper layer processing */
			if(entry->interface->upper) {
				NG_FWD_NEW_DATA(error, item, entry->interface->upper, m);
			}

			return error;

		} else if(entry->entry.type == LIB_L3VPN) {
			/* L3VPN switching */
							
			/* if we are at the bottom of the stack - set ethernet type to ip */
			if(s) {
				eh->ether_type = htons(ETHERTYPE_IP);
			}

			/* remove label only */
			remove_label(m);

#ifdef _DEBUG
			printf("ifindex %u\n", entry->ifIndex);
#endif

			/* forward frame */
			mbuf_ip = m_copym(m, ETHER_HDR_LEN, sizeof(struct ip), M_DONTWAIT);
			ip = mtod(mbuf_ip, struct ip *);

			copy = m_dup(m, M_DONTWAIT);
			if(!copy) {
				return (ENOMEM);
			}
			m_adj(copy, ETHER_HDR_LEN);

			return mpls_ether_forward(item, entry->interface, ip->ip_dst, m, copy);
		}

		/* should never happen */
		NG_FREE_ITEM(item);

	} else {
		/* non mpls packet */

		/* check VPN base for this interface */
		entry = mpls_get_vpn_entry(interface);
		if(entry && (entry->entry.type == LIB_L2VPN || eh->ether_type == htons(ETHERTYPE_IP))) {
			/* L2 or L3 VPN */

			/* get ip header */
			mbuf_ip = m_copym(m, ETHER_HDR_LEN, sizeof(struct ip), M_DONTWAIT);
			ip = mtod(mbuf_ip, struct ip *);
			ttl = ip->ip_ttl;

			len = ETHER_MPLS_ENCAP_LEN;

			/* find LIB entry to transport packet to VPN endpoint (entry->entry.nexthop) */
			transport_entry = mpls_get_entry_by_address(entry->entry.nexthop);
			if(!transport_entry) {
				NG_FREE_ITEM(item);
				return (EINVAL);
			}

			if(!mpls_should_pop_label(transport_entry->entry.remote)) {
				len += ETHER_MPLS_ENCAP_LEN;
			}

			/* for L2 VPN we need a new ethernet header */
			if(entry->entry.type == LIB_L2VPN) {
				len += ETHER_HDR_LEN;
			}

			/* extend packet TODO: ip fragmentation */
			M_PREPEND(m, len, M_DONTWAIT);

			/* make ETHER_HDR_LEN + len bytes lie consecutivly */
			len_ext = len + ETHER_HDR_LEN;
			if(m == NULL || (m->m_len < len_ext && (m = m_pullup(m, len_ext)) == NULL)) {
				NG_FREE_ITEM(item);
				return (ENOMEM);
			}

			if(entry->entry.type != LIB_L2VPN) {
				/* move original ether header to the beginig */
				bcopy(mtod(m, char *) + len, mtod(m, char *), ETHER_HDR_LEN);
			}

			/* set ether type to mpls */
			eh = mtod(m, struct ether_header *);
			eh->ether_type = htons(ETHERTYPE_MPLS);

			label_stack = (uint32_t *)(eh + 1);

			if(!mpls_should_pop_label(transport_entry->entry.remote)) {
				/* push transport label */
				setLabel(label_stack++, transport_entry->entry.remote, 0, 0, ttl - 1);
			}
			/* push tunnel label */
			setLabel(label_stack, entry->entry.local, 0, 1, ttl - 1);

			/* copy packet's mbuf for reinjecting by arp */
			copy = m_dup(m, M_DONTWAIT);
			if(copy == NULL) {
				return (ENOMEM);
			}
					
			/* forward this packet */
			return mpls_ether_forward(item, transport_entry->interface, transport_entry->entry.nexthop, m, copy);
		}
					
		/* forward to upper for further processing */
		if(interface->upper) {
			NG_FWD_NEW_DATA(error, item, interface->upper, m);
			return 0;
		}

	}

	return 0;
}


/*
============
processUpperEthernet
============
*/
int mpls_ether_upper(const priv_p priv, interface_p interface, item_p item, struct mbuf *m)
{
	int error;
	size_t len;
	struct ether_header *eh;
	struct mbuf *copy, *mbuf_ip;
	struct ip *ip;
	mpls_lib_entry_p entry;
	
	/* get mbuf after L2 header */
	mbuf_ip = m_copym(m, ETHER_HDR_LEN, sizeof(struct ip), M_DONTWAIT);

	eh = mtod(mbuf_ip, struct ether_header *);
	if(eh->ether_type == htons(ETHERTYPE_MPLS)) {
		/* if it's an mpls packet reinjected by arplookup then strip extra header that was added by mpls_ether_lower */
		m_adj(m, ETHER_HDR_LEN);

#ifdef _DEBUG
		/* print top label */
		uint32_t label;
		uint8_t exp, s, ttl;
		size_t len;

		len = sizeof(struct ether_header) + sizeof(label);
		if(m->m_len < len && (m = m_pullup(m, len)) == NULL) {
			NG_FREE_ITEM(item);
			return (EINVAL);
		}
		eh = mtod(m, struct ether_header *);
		getLabel(eh + 1, &label, &exp, &s, &ttl);
		printf("upper: reinjected by arp packet's top label [%u %u %u %u]\n", label, exp, s, ttl);
#endif
	} else {
		ip = mtod(mbuf_ip, struct ip *);

		/* FTN lookup */
		entry = mpls_get_entry_by_address(ip->ip_dst);
		if(entry && !mpls_should_pop_label(entry->entry.remote) && entry->interface->lower) {
			copy = m_dup(m, M_DONTWAIT);
			if(!copy) {
				NG_FREE_ITEM(item);
				return (ENOMEM);
			}
			m_adj(copy, ETHER_HDR_LEN);

			/* extend packet */
			M_PREPEND(m, ETHER_MPLS_ENCAP_LEN, M_DONTWAIT);
			len = sizeof(struct ether_header) + ETHER_MPLS_ENCAP_LEN;
			if(m == NULL || (m->m_len < len && (m = m_pullup(m, len)) == NULL)) {
				NG_FREE_ITEM(item);
				return (ENOMEM);
			}

			/* move original ether header to the beginig */
			bcopy(mtod(m, char *) + ETHER_MPLS_ENCAP_LEN, mtod(m, char *), ETHER_HDR_LEN);
			
			/* convert it to mpls header */
			eh = mtod(m, struct ether_header *);
			eh->ether_type = htons(ETHERTYPE_MPLS);

			/* push label */
			setLabel(eh + 1, entry->entry.remote, 0, 1, ip->ip_ttl - 1);
				
			/* forward this packet */
			return mpls_ether_forward(item, entry->interface, entry->entry.nexthop, m, copy);
		}
	}
		
	/* forward this packet */
	if(interface->lower) {
		NG_FWD_NEW_DATA(error, item, interface->lower, m);
		return 0;
	} else {
		NG_FREE_ITEM(item);
		return EINVAL;
	}
}
