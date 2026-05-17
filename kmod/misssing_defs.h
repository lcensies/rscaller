
typedef int utrap_entry_t;
typedef void *utrap_handler_t;

/* cgroup_namespace is defined in linux/cgroup.h (not linux/cgroup_namespace.h) */
#include <linux/cgroup.h>

/* vm_flags_set() / vm_flags_clear() introduced in 6.3 (vm_flags made const).
 * In 6.15+ these are GPL-only; use vm_flags_reset() for non-GPL modules on 6.15+.
 * For < 6.3: direct assignment is fine. */
#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 3, 0)
#define vm_flags_set(vma, flags)   ((vma)->vm_flags |= (flags))
#define vm_flags_clear(vma, flags) ((vma)->vm_flags &= ~(flags))
#endif

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

#ifndef u32
#define u32 uint32_t
#endif

#ifndef u64
#define u64 uint64_t
#endif

typedef unsigned int __u32;
typedef __u32 u32;
typedef u32			uint32_t;

#ifndef __kernel_long_t
typedef long		__kernel_long_t;
typedef unsigned long	__kernel_ulong_t;
#endif


typedef __kernel_long_t	__kernel_off_t;
typedef long long	__kernel_loff_t;
typedef __kernel_long_t	__kernel_old_time_t;

typedef unsigned short __kernel_old_uid_t;
typedef unsigned short __kernel_old_gid_t;
#define __kernel_old_uid_t __kernel_old_uid_t

// typedef struct {
// 	s64 counter;
// } atomic64_tdf

// union pl_args {
// 	struct setargs {
// 		char __user *path;
// 		long follow;
// 		long nbytes;
// 		char __user *buf;
// 	} set;
// 	struct fsetargs {
// 		long fd;
// 		long nbytes;
// 		char __user *buf;
// 	} fset;
// 	struct getargs {
// 		char __user *path;
// 		long follow;
// 		struct proplistname_args __user *name_args;
// 		long nbytes;
// 		char __user *buf;
// 		int __user *min_buf_size;
// 	} get;
// 	struct fgetargs {
// 		long fd;
// 		struct proplistname_args __user *name_args;
// 		long nbytes;
// 		char __user *buf;
// 		int __user *min_buf_size;
// 	} fget;
// 	struct delargs {
// 		char __user *path;
// 		long follow;
// 		struct proplistname_args __user *name_args;
// 	} del;
// 	struct fdelargs {
// 		long fd;
// 		struct proplistname_args __user *name_args;
// 	} fdel;
// };

typedef int utrap_entry_t;
typedef void *utrap_handler_t;

// typedef unsigned char		u8;
// typedef unsigned short		u16;
// typedef unsigned int		u32;
// typedef unsigned long long	u64;
// typedef signed char		s8;
// typedef short			s16;
// typedef int			s32;
// typedef long long		s64;

// /* required for opal-api.h */
// // typedef u8  uint8_t;
// // typedef u16 uint16_t;
// // typedef u32 uint32_t;
// // typedef u64 uint64_t;
// // typedef s8  int8_t;
// // typedef s16 int16_t;
// // typedef s32 int32_t;
// // typedef s64 int64_t;


// typedef u32 compat_size_t;
// typedef s32 compat_ssize_t;
// typedef s32 compat_clock_t;
// typedef s32 compat_pid_t;
// typedef u32 compat_ino_t;
// typedef s32 compat_off_t;
// typedef s64 compat_loff_t;
// typedef s32 compat_daddr_t;
// typedef s32 compat_timer_t;
// typedef s32 compat_key_t;
// typedef s16 compat_short_t;
// typedef s32 compat_int_t;
// typedef s32 compat_long_t;
// typedef u16 compat_ushort_t;
// typedef u32 compat_uint_t;
// typedef u32 compat_ulong_t;
// typedef u32 compat_uptr_t;
// typedef u32 compat_aio_context_t;