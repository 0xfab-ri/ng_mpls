#include "ng_mpls.h"

/* LIB. label information base */

LIST_HEAD(mpls_lib_head, mpls_lib_entry);

static int					mpls_lib_size = 0;
static struct mpls_lib_head	mpls_lib;


/* prefixes_equal: checks if prefixes are the same */
static int prefixes_equal(struct ng_mpls_prefix *a, struct ng_mpls_prefix *b)
{
	return (a->length == b->length && a->prefix.s_addr == b->prefix.s_addr);
}


/* prefix_contains: checks if the prefix contains the address */
static int prefix_contains(struct ng_mpls_prefix *prefix, struct in_addr address)
{
	uint32_t a = ntohl(address.s_addr) >> (32 - prefix->length);
	uint32_t b = ntohl(prefix->prefix.s_addr) >> (32 - prefix->length);
	return (a == b);
}


static void _mpls_delete_entry(mpls_lib_entry_p entry)
{
	LIST_REMOVE(entry, next);
	FREE(entry, M_NETGRAPH);
	mpls_lib_size--;
}


/* mpls_init: initializes LIB */
void mpls_init()
{
	LIST_INIT(&mpls_lib);
}


/* mpls_shutdown: frees LIB memory */
void mpls_shutdown()
{
	mpls_lib_entry_p entry;

	while(!LIST_EMPTY(&mpls_lib)) {
		entry = LIST_FIRST(&mpls_lib);
		_mpls_delete_entry(entry);
	}

	mpls_lib_size = 0;
}


/* mpls_add_entry: adds a new entry to the LIB */
void mpls_add_entry(struct ng_mpls_lib_entry *info, interface_p interface)
{
	mpls_lib_entry_p entry;

	if(!info || (info->type != LIB_IN && !interface)) {
		return;
	}

	LIST_FOREACH(entry, &mpls_lib, next) {
		if(prefixes_equal(&entry->entry.prefix, &info->prefix)) {
			break;
		}
	}

	if(!entry) {
		MALLOC(entry, mpls_lib_entry_p, sizeof(*entry), M_NETGRAPH, M_NOWAIT | M_ZERO);
		if(!entry) {
			printf("mpls_add_entry: not enough memory\n");
			return;
		}

		entry->entry = *info;
		entry->interface = interface;
	
		LIST_INSERT_HEAD(&mpls_lib, entry, next);

		mpls_lib_size++;
	} else {
		if(info->type == LIB_IN) {
			entry->entry.local = info->local;
		} else {
			entry->entry.type = LIB_NORMAL;
			entry->entry.remote = info->remote;
			entry->entry.nexthop = info->nexthop;
			entry->interface = interface;
		}
	}
}


/* mpls_delete_entry: deletes entry from LIB by index */
void mpls_delete_entry(uint32_t index)
{
	mpls_lib_entry_p entry;

	if(index < 0 || index >= mpls_lib_size) {
		return;
	}
	
	LIST_FOREACH(entry, &mpls_lib, next) {
		if(index-- == 0) {
			_mpls_delete_entry(entry);
			break;
		}
	}
}


/* mpls_delete_local: deletes local binding from LIB */
void mpls_delete_local(int32_t local)
{
	mpls_lib_entry_p entry;

	if(local <= 0) {
		return;
	}

	LIST_FOREACH(entry, &mpls_lib, next) {
		if(entry->entry.local == local) {
			entry->entry.local = -1;

			/* remove entry if it has no remote binding */
			if(!entry->interface) {
				_mpls_delete_entry(entry);
			}
			break;
		}
	}
}


/* mpls_delete_remote: delete remote binding from LIB */
void mpls_delete_remote(struct ng_mpls_lib_entry *remote, interface_p interface)
{
	mpls_lib_entry_p entry;

	LIST_FOREACH(entry, &mpls_lib, next) {
		if(!entry->interface) {
			continue;
		}

		if(entry->entry.remote == remote->remote
				&& prefixes_equal(&entry->entry.prefix, &remote->prefix)
				&& entry->entry.nexthop.s_addr == remote->nexthop.s_addr
				&& entry->interface == interface) {
			entry->entry.remote = -1;
			entry->entry.nexthop.s_addr = 0;
			entry->interface = NULL;

			/* remove entry if it has no local binding */
			if(entry->entry.local == -1) {
				_mpls_delete_entry(entry);
			}
			break;
		}
	}
}


/* mpls_delete_by_labels: deletes entry from LIB by local-remote labels pair */
void mpls_delete_by_labels(int local, int remote)
{
	mpls_lib_entry_p entry;

	LIST_FOREACH(entry, &mpls_lib, next) {
		if(entry->entry.type == LIB_NORMAL && entry->entry.local == local && entry->entry.remote == remote) {
			_mpls_delete_entry(entry);
			break;
		}
	}
}


/* mpls_get_lib_size: returns number of LIB entries */
uint32_t mpls_get_lib_size()
{
	return mpls_lib_size;
}


/* mpls_get_lib: fills in the LIB structure */
void mpls_get_lib(struct ng_mpls_lib *lib)
{
	int i = 0;
	mpls_lib_entry_p entry;

	if(!lib) {
		return;
	}

	lib->size = mpls_lib_size;
	LIST_FOREACH(entry, &mpls_lib, next) {
		lib->entries[i] = entry->entry;
		i++;
	}
}


/* mpls_add_xc */
void mpls_add_xc(int32_t local, int32_t remote)
{
	mpls_lib_entry_p entry;

	LIST_FOREACH(entry, &mpls_lib, next) {
		if(entry->entry.type == LIB_NORMAL && entry->entry.remote == remote) {
			entry->entry.local = local;
			break;
		}
	}
}


/* mpls_delete_xc */
void mpls_delete_xc(int32_t local, int32_t remote)
{
	mpls_lib_entry_p entry;

	LIST_FOREACH(entry, &mpls_lib, next) {
		if(entry->entry.type == LIB_NORMAL && entry->entry.local == local && entry->entry.remote == remote) {
			entry->entry.local = -1;
			break;
		}
	}
}


/* mpls_get_label_by_prefix: returns label binded to the prefix */
int32_t mpls_get_label_by_prefix(struct ng_mpls_prefix *prefix)
{
	mpls_lib_entry_p entry;

	LIST_FOREACH(entry, &mpls_lib, next) {
		if(!entry->entry.prefix.prefix.s_addr || !entry->entry.prefix.length) {
			continue;
		}

		if(prefixes_equal(&entry->entry.prefix, prefix)) {
			return entry->entry.local;
		}
	}

	return -1;
}


/* mpls_get_entry_by_label: returns LIB entry by label (ILM lookup) */
mpls_lib_entry_p mpls_get_entry_by_label(int32_t label)
{
	mpls_lib_entry_p entry;

	LIST_FOREACH(entry, &mpls_lib, next) {
		if(entry->entry.local == label) {
			return entry;
		}
	}

	return NULL;
}


/* mpls_get_entry_by_address: returns LIB entry by address (FTN lookup) */
mpls_lib_entry_p mpls_get_entry_by_address(struct in_addr address)
{
	mpls_lib_entry_p entry;

	LIST_FOREACH(entry, &mpls_lib, next) {
		if(entry->entry.type == LIB_NORMAL && prefix_contains(&entry->entry.prefix, address)) {
			return entry;
		}
	}

	return NULL;
}


/* mpls_get_vpn_entry: returns L2 or L3 vpn for the interface */
mpls_lib_entry_p mpls_get_vpn_entry(interface_p interface)
{
	mpls_lib_entry_p entry;

	LIST_FOREACH(entry, &mpls_lib, next) {
		if((entry->entry.type == LIB_L2VPN || entry->entry.type == LIB_L3VPN) && entry->interface == interface) {
			return entry;
		}
	}

	return NULL;
}
