#include "ng_mpls.h"


/*    NETGRAPH NODE DESCRIPTION    */


/* netgraph methods */
static ng_constructor_t ng_mpls_constructor;
static ng_rcvmsg_t ng_mpls_rcvmsg;
static ng_shutdown_t ng_mpls_shutdown;
static ng_newhook_t ng_mpls_newhook;
static ng_rcvdata_t ng_mpls_rcvdata;
static ng_disconnect_t ng_mpls_disconnect;

/* parse types definitions */

/* struct ng_mpls_prefix */
static const struct ng_parse_struct_field ng_mpls_prefix_fields[] = {
	{ "prefix", &ng_parse_ipaddr_type },
	{ "length", &ng_parse_uint8_type },
	{ NULL }
};

static const struct ng_parse_type ng_parse_mpls_prefix_type = {
	&ng_parse_struct_type,
	&ng_mpls_prefix_fields
};


/* struct ng_mpls_lib_entry */
static const struct ng_parse_struct_field ng_mpls_lib_entry_fields[] = {
	{ "type", &ng_parse_uint8_type },
	{ "local", &ng_parse_int32_type },
	{ "remote", &ng_parse_int32_type },
	{ "prefix", &ng_parse_mpls_prefix_type },
	{ "if_name", &ng_parse_string_type },
	{ "nexthop", &ng_parse_ipaddr_type },
	{ NULL }
};

static const struct ng_parse_type ng_parse_mpls_lib_entry_type = {
	&ng_parse_struct_type,
	&ng_mpls_lib_entry_fields
};


/* struct ng_mpls_lib */
static int ng_parse_mpls_lib_size(const struct ng_parse_type *type, const u_char *start, const u_char *buf)
{
	return ((const struct ng_mpls_lib *)(buf - sizeof(uint32_t)))->size;
}

static const struct ng_parse_array_info ng_parse_mpls_lib_entries_info = {
	&ng_parse_mpls_lib_entry_type,
	ng_parse_mpls_lib_size
};

static const struct ng_parse_type ng_parse_mpls_lib_entries_type = {
	&ng_parse_array_type,
	&ng_parse_mpls_lib_entries_info
};

static const struct ng_parse_struct_field ng_parse_mpls_lib_fields[] = {
	{ "size", &ng_parse_uint32_type },
	{ "entries", &ng_parse_mpls_lib_entries_type },
	{ NULL }
};

static const struct ng_parse_type ng_parse_mpls_lib_type = {
	&ng_parse_struct_type,
	&ng_parse_mpls_lib_fields
};


/* list of commands and how to convert arguments to/from ASCII */
static const struct ng_cmdlist ng_mpls_cmds[] = {
	{ NGM_MPLS_COOKIE, NGM_MPLS_ADD, "add", &ng_parse_mpls_lib_entry_type, NULL },
	{ NGM_MPLS_COOKIE, NGM_MPLS_DELETE, "delete", &ng_parse_uint32_type, NULL },
	{ NGM_MPLS_COOKIE, NGM_MPLS_DELETE_LOCAL, "delete_local", &ng_parse_mpls_lib_entry_type, NULL },
	{ NGM_MPLS_COOKIE, NGM_MPLS_DELETE_REMOTE, "delete_remote", &ng_parse_mpls_lib_entry_type, NULL },
	{ NGM_MPLS_COOKIE, NGM_MPLS_GET, "get", &ng_parse_mpls_prefix_type, &ng_parse_int32_type },
	{ NGM_MPLS_COOKIE, NGM_MPLS_SHOW, "show", NULL, &ng_parse_mpls_lib_type },
	{ 0 }
};


/* netgraph type descriptor */
static struct ng_type ng_mpls_typestruct = {
	.version =		NG_ABI_VERSION,
	.name =			NG_MPLS_NODE_TYPE,
	.constructor =	ng_mpls_constructor,
	.rcvmsg =		ng_mpls_rcvmsg,
	.shutdown =		ng_mpls_shutdown,
	.newhook =		ng_mpls_newhook,
	.rcvdata =		ng_mpls_rcvdata,
	.disconnect =	ng_mpls_disconnect,
	.cmdlist =		ng_mpls_cmds,
};
NETGRAPH_INIT(mpls, &ng_mpls_typestruct);


/*    IMPLEMENTATION    */


/* ng_mpls_constructor: handles node creation */
static int ng_mpls_constructor(node_p node)
{
	priv_p priv;
	
	MALLOC(priv, priv_p, sizeof(*priv), M_NETGRAPH, M_NOWAIT | M_ZERO);
	if(priv == NULL) {
		return (ENOMEM);
	}

	priv->num_interfaces = 0;
	memset(priv->interfaces, 0, sizeof(priv->interfaces));
	NG_NODE_SET_PRIVATE(node, priv);
	priv->node = node;

	mpls_init();

	return (0);
}


/* find_if_index_by_name: returns interface index by name */
static unsigned int find_if_index_by_name(const priv_p priv, const char *name)
{
	int i;

	for(i = 0; i < NG_MPLS_MAX_INTERFACES; i++) {
		struct ifnet *ifnet = priv->interfaces[i].ifnet;
		if(ifnet && strcmp(ifnet->if_xname, name) == 0) {
			return i;
		}
	}

	return NG_MPLS_MAX_INTERFACES;
}


static interface_p find_interface_by_name(const priv_p priv, const char *name)
{
	uint32_t index = find_if_index_by_name(priv, name);
	
	if(index < 0 || index >= NG_MPLS_MAX_INTERFACES) {
		return NULL;
	}

	return &priv->interfaces[index];
}


/* add_interface: adds an interface to the node's internal interface list */
static interface_p add_interface(const priv_p priv, hook_p hook, const char *name, const char *if_name)
{
	int index;
	interface_p interface;

	if(priv->num_interfaces == NG_MPLS_MAX_INTERFACES) {
		return NULL;
	}
	
	index = priv->num_interfaces;

	interface = &priv->interfaces[index];
	interface->index = index;
	interface->type = IF_ETHER;
	interface->ifnet = ifunit(if_name);
	if(!interface->ifnet) {
#ifdef _DEBUG
		printf("could not find ifnet for %s (hook %s)\n", if_name, name);
#endif
		return NULL;
	}
	
	NG_HOOK_SET_PRIVATE(hook, interface);
	priv->num_interfaces++;

	return interface;
}


/* ng_mpls_newhook: handles hook creation */
static int ng_mpls_newhook(node_p node, hook_p hook, const char *name)
{
	int len, len_lower, len_upper;
	const char *if_name;
	uint8_t if_index;
	interface_p interface;
	const priv_p priv = NG_NODE_PRIVATE(node);

	len = strlen(name);
	len_lower = strlen(NG_MPLS_HOOK_LOWER);
	len_upper = strlen(NG_MPLS_HOOK_LOWER);
	
	if(len > len_lower && strncmp(name, NG_MPLS_HOOK_LOWER, len_lower) == 0) {
		/* if hook name starts with NG_MPLS_HOOK_LOWER ("lower_") and not equal to it */

		if_name = name + len_lower;

		/* find interface's index by name */
		if_index = find_if_index_by_name(priv, if_name);
		if(if_index == NG_MPLS_MAX_INTERFACES) {
			/* if there is no such interface then add it */
			interface = add_interface(priv, hook, name, if_name);
			if(!interface) {
				return (EINVAL);
			}
		} else {
			/* if interface already in table then just attach it to the hook */
			interface = &priv->interfaces[if_index];
			if(interface->lower != NULL) {
				/* lower hook is already connnected */
				return (EISCONN);
			}
			NG_HOOK_SET_PRIVATE(hook, interface);
		}

		/* save a reference to the hook */
		interface->lower = hook;
	} else if(len > len_upper && strncmp(name, NG_MPLS_HOOK_UPPER, len_upper) == 0) {
		/* if hook name starts with NG_MPLS_HOOK_UPPER ("upper_") and not equal to it then use the same logic as above */

		if_name = name + len_upper;
		if_index = find_if_index_by_name(priv, if_name);

		if(if_index == NG_MPLS_MAX_INTERFACES) {
			interface = add_interface(priv, hook, name, if_name);
			if(!interface) {
				return (EINVAL);
			}
		} else {
			interface = &priv->interfaces[if_index];
			if(interface->upper != NULL) {
				return (EISCONN);
			}
			NG_HOOK_SET_PRIVATE(hook, interface);
		}

		interface->upper = hook;
	} else {
		/* unsupported hook name */
		return (EINVAL);
	}
	
	return (0);
}


/* ng_mpls_rcvmsg: processes a control message */
static int ng_mpls_rcvmsg(node_p node, item_p item, hook_p lasthook)
{
	const priv_p priv = NG_NODE_PRIVATE(node);
	struct ng_mesg *msg, *resp = NULL;
	struct ng_mpls_prefix *prefix;
	struct ng_mpls_lib_entry *entry;
	int error = 0;
	uint32_t size;
	interface_p interface;

	NGI_GET_MSG(item, msg);

	if(msg->header.typecookie == NGM_MPLS_COOKIE) {
		switch(msg->header.cmd) {
		/* add */
		case NGM_MPLS_ADD:
			if(msg->header.arglen != sizeof(struct ng_mpls_lib_entry)) {
				error = EINVAL;
				break;
			}
			
			entry = (struct ng_mpls_lib_entry *)msg->data;
			if(entry->type == LIB_IN) {
				mpls_add_entry(entry, NULL);
			} else {
				interface = find_interface_by_name(priv, entry->if_name);
				if(!interface || !interface->lower) {
					error = EINVAL;
					break;
				}

				mpls_add_entry(entry, interface);
			}
			break;
		
		/* delete */
		case NGM_MPLS_DELETE:
			if(msg->header.arglen != sizeof(int32_t)) {
				error = EINVAL;
				break;
			}

			mpls_delete_entry(*((uint32_t *)msg->data));
			break;

		/* delete_local */
		case NGM_MPLS_DELETE_LOCAL:
			if(msg->header.arglen != sizeof(struct ng_mpls_lib_entry)) {
				error = EINVAL;
				break;
			}
			
			entry = (struct ng_mpls_lib_entry *)msg->data;
			mpls_delete_local(entry->local);
			break;

		/* delete_remote */
		case NGM_MPLS_DELETE_REMOTE:
			if(msg->header.arglen != sizeof(struct ng_mpls_lib_entry)) {
				error = EINVAL;
				break;
			}
			
			entry = (struct ng_mpls_lib_entry *)msg->data;
			interface = find_interface_by_name(priv, entry->if_name);
			mpls_delete_remote(entry, interface);
			break;

		/* add_xc */
		case NGM_MPLS_ADD_XC:
			if(msg->header.arglen != sizeof(struct ng_mpls_lib_entry)) {
				error = EINVAL;
				break;
			}
			
			entry = (struct ng_mpls_lib_entry *)msg->data;
			if(entry->type == LIB_NORMAL) {
				mpls_add_xc(entry->local, entry->remote);
			}
			break;

		/* delete_xc */
		case NGM_MPLS_DELETE_XC:
			if(msg->header.arglen != sizeof(struct ng_mpls_lib_entry)) {
				error = EINVAL;
				break;
			}
			
			entry = (struct ng_mpls_lib_entry *)msg->data;
			mpls_delete_xc(entry->local, entry->remote);
			break;
	
		/* get */
		case NGM_MPLS_GET:
			if(msg->header.arglen != sizeof(struct ng_mpls_prefix)) {
				error = EINVAL;
				break;
			}

			prefix = (struct ng_mpls_prefix *)msg->data;

			NG_MKRESPONSE(resp, msg, sizeof(int32_t), M_NOWAIT);
			if(!resp) {
				error = ENOMEM;
				break;
			}

			*((int32_t *)resp->data) = mpls_get_label_by_prefix(prefix);
			break;

		/* show */
		case NGM_MPLS_SHOW:
			size = mpls_get_lib_size();

			NG_MKRESPONSE(resp, msg, sizeof(struct ng_mpls_lib) + size * sizeof(struct ng_mpls_lib_entry), M_NOWAIT);
			if(!resp) {
				error = ENOMEM;
				break;
			}
		
			mpls_get_lib((struct ng_mpls_lib *)resp->data);
			break;

		default:
			error = EINVAL;
			break;
		}
	} else {
		error = EINVAL;
	}
	
	NG_RESPOND_MSG(error, node, item, resp);
	NG_FREE_MSG(msg);

	return (error);
}


/* ng_mpls_rcvdata: processes the received data */
static int ng_mpls_rcvdata(hook_p hook, item_p item)
{
	const priv_p priv = NG_NODE_PRIVATE(NG_HOOK_NODE(hook));
	interface_p interface = NG_HOOK_PRIVATE(hook);
	struct mbuf *m;
	int error;

	if(!interface) {
		return 0;
	}

	NGI_GET_M(item, m);

	if(interface->lower && hook == interface->lower) {
		/* lower hook (unlabeled or mpls packet). forwarding */

		if(interface->type == IF_ETHER) {
			return mpls_ether_lower(priv, interface, item, m);
		}
		if(interface->upper) {
			NG_FWD_ITEM_HOOK(error, item, interface->upper);
		}
	} else if(interface->upper && hook == interface->upper) {
		/* upper hook (unlabeled or reinjected packet). add label if needed and forward to lower */

		if(interface->type == IF_ETHER) {
			return mpls_ether_upper(priv, interface, item, m);
		}
		if(interface->lower) {
			NG_FWD_ITEM_HOOK(error, item, interface->lower);
		}
	}

	panic("%s: weird hook", __func__);
#ifdef RESTARTABLE_PANICS /* so we don't get an error msg in LINT */
	return NULL;
#endif

	return 0;
}


/* ng_mpls_disconnect: handles hook deletion */
static int ng_mpls_disconnect(hook_p hook)
{
	node_p node = NG_HOOK_NODE(hook);
	interface_p interface = NG_HOOK_PRIVATE(hook);

	if(interface) {
		/* remove a reference to the hook from the interface */
		if(hook == interface->lower) {
			interface->lower = NULL;
		} else {
			interface->upper = NULL;
		}

		if(!interface->lower && !interface->upper) {
			/* invalidate ifnet reference if both hooks was disconnected */
			interface->ifnet = NULL;
		}
	}
	
	if(NG_NODE_NUMHOOKS(node) == 0 && NG_NODE_IS_VALID(node)) {
		/* shutdown node when there is no hooks */
		ng_rmnode_self(node);
	}
	
	return (0);
}


/* ng_mpls_shutdown: handles node shutdown process */
static int ng_mpls_shutdown(node_p node)
{
	const priv_p priv = NG_NODE_PRIVATE(node);

	/* free label information base */
	mpls_shutdown();
	
	/* free private info */
	NG_NODE_SET_PRIVATE(node, NULL);
	NG_NODE_UNREF(priv->node);
	FREE(priv, M_NETGRAPH);
	
	return (0);
}
