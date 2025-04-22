
typedef int utrap_entry_t;
typedef void *utrap_handler_t;

enum pl_code {
	PL_SET = 1, PL_FSET = 2,
	PL_GET = 3, PL_FGET = 4,
	PL_DEL = 5, PL_FDEL = 6
};

enum landlock_rule_type {
	/**
	 * @LANDLOCK_RULE_PATH_BENEATH: Type of a &struct
	 * landlock_path_beneath_attr .
	 */
	LANDLOCK_RULE_PATH_BENEATH = 1,
	/**
	 * @LANDLOCK_RULE_NET_PORT: Type of a &struct
	 * landlock_net_port_attr .
	 */
	LANDLOCK_RULE_NET_PORT,
};

#ifndef __NR_getdents
#define __NR_getdents 141
#endif

typedef __kernel_long_t	__kernel_off_t;
typedef long long	__kernel_loff_t;
typedef __kernel_long_t	__kernel_old_time_t;