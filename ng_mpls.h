#ifndef _NG_MPLS_H_
#define _NG_MPLS_H_

/* includes */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ctype.h>

#include <net/if.h>
#include <net/if_types.h>
#include <net/if_var.h>

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#include <netgraph/ng_message.h>
#include <netgraph/netgraph.h>
#include <netgraph/ng_parse.h>

#include "public.h"


/* interface type */
enum {
	IF_ETHER	= 0
};

/* an internal interface instance */
struct ng_mpls_interface {
	uint8_t			index;		/* internal interface index */
	uint8_t			type;		/* interface type */
	hook_p			lower;		/* lower layer hook ref */
	hook_p			upper;		/* upper layer hook ref */
	struct ifnet	*ifnet;		/* system interface ref */
};
typedef struct ng_mpls_interface *interface_p;

/* node's private info */
struct ng_mpls_private {
	node_p						node;
	uint8_t						num_interfaces;
	struct ng_mpls_interface	interfaces[NG_MPLS_MAX_INTERFACES];
};
typedef struct ng_mpls_private *priv_p;

/* LIB. label information base */
struct mpls_lib_entry {
	struct ng_mpls_lib_entry	entry;			/* entry */
	interface_p					interface;		/* outgoing interface */
	LIST_ENTRY(mpls_lib_entry)	next;			/* linked list of LIB entries */
};
typedef struct mpls_lib_entry *mpls_lib_entry_p;

/* common */
static inline void setLabel(void *addr, uint32_t label, uint8_t exp, uint8_t s, uint8_t ttl) {
	if(addr != NULL)
		*((uint32_t *)addr) = htonl(((label & 0xfffff) << 12) | ((exp & 0x7) << 9) | ((s & 0x1) << 8) | ttl);
}

static inline void getLabel(const void *addr, uint32_t *label, uint8_t *exp, uint8_t *s, uint8_t *ttl) {
	uint32_t val;

	if(!addr)
		return;

	val = ntohl(*((const uint32_t *)addr));
	if(label)
		*label = (val & 0xfffff000) >> 12;
	if(exp)
		*exp = (val & 0x00000e00) >> 9;
	if(s)
		*s = (val & 0x00000100) >> 8;
	if(ttl)
		*ttl = (val & 0xff);
}


/* lib.c */
void mpls_init(void);
void mpls_shutdown(void);

uint32_t mpls_get_lib_size(void);
void mpls_get_lib(struct ng_mpls_lib *lib);

void mpls_add_entry(struct ng_mpls_lib_entry *entry, interface_p interface);
void mpls_delete_entry(uint32_t index);
void mpls_delete_local(int32_t local);
void mpls_delete_remote(struct ng_mpls_lib_entry *entry, interface_p interface);
void mpls_delete_by_labels(int32_t local, int32_t remote);

void mpls_add_xc(int32_t local, int32_t remote);
void mpls_delete_xc(int32_t local, int32_t remote);

int32_t mpls_get_label_by_prefix(struct ng_mpls_prefix *prefix);
mpls_lib_entry_p mpls_get_entry_by_label(int32_t label);
mpls_lib_entry_p mpls_get_entry_by_address(struct in_addr address);
mpls_lib_entry_p mpls_get_vpn_entry(interface_p interface);


/* ether.c */
int mpls_ether_lower(const priv_p priv, interface_p interface, item_p item, struct mbuf *m);
int mpls_ether_upper(const priv_p priv, interface_p interface, item_p item, struct mbuf *m);


#endif /* _NG_MPLS_H_ */
