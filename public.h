#ifndef _NG_MPLS_PUBLIC_H_
#define _NG_MPLS_PUBLIC_H_

/* ng_mpls module's public interface */

#define NG_MPLS_MAX_INTERFACES 128

/* Node type name and magic cookie */
#define NG_MPLS_NODE_TYPE	"mpls"
#define NGM_MPLS_COOKIE		1109054581

/* Hook names */
#define NG_MPLS_HOOK_LOWER	"lower_"
#define NG_MPLS_HOOK_UPPER	"upper_"

#define MPLS_IMPLICIT_NULL	3

/* Commands */
enum {
	NGM_MPLS_ADD = 1,
	NGM_MPLS_DELETE,
	NGM_MPLS_DELETE_LOCAL,
	NGM_MPLS_DELETE_REMOTE,
	NGM_MPLS_ADD_XC,
	NGM_MPLS_DELETE_XC,
	NGM_MPLS_GET,
	NGM_MPLS_SHOW,
	NGM_MPLS_VPN_ADD,
	NGM_MPLS_VPN_DEL,
	NGM_MPLS_VPN_SHOW
};

/* LIB entry type */
enum {
	LIB_IN = 0,
	LIB_NORMAL,
	LIB_L2VPN,
	LIB_L3VPN
};

/* Command structures */
struct ng_mpls_prefix {
	struct in_addr	prefix;
	uint8_t			length;
};

struct ng_mpls_lib_entry {
	uint8_t					type;
	int32_t					local;
	int32_t					remote;
	struct ng_mpls_prefix	prefix;
	char					if_name[IFNAMSIZ];
	struct in_addr			nexthop;
};

struct ng_mpls_lib {
	uint32_t					size;
	struct ng_mpls_lib_entry	entries[0];
};

static inline int mpls_should_pop_label(int32_t label) {
	return label < 0 || label == MPLS_IMPLICIT_NULL;
}

#endif /* _NG_MPLS_PUBLIC_H_ */
