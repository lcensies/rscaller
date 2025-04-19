
typedef union {
	int int_type;
	unsigned long unsigned_long_type;
	unsigned int unsigned_int_type;
	char * char_ptr_type;
	u32 u32_type;
	size_t size_t_type;
	void * void_ptr_type;
	pid_t pid_t_type;
	compat_size_t compat_size_t_type;
	struct __kernel_timespec * struct___kernel_timespec_ptr_type;
	int * int_ptr_type;
	struct old_timespec32 * struct_old_timespec32_ptr_type;
	struct iovec * struct_iovec_ptr_type;
	clockid_t clockid_t_type;
	compat_ulong_t compat_ulong_t_type;
	long long_type;
	umode_t umode_t_type;
	compat_sigset_t * compat_sigset_t_ptr_type;
	uid_t uid_t_type;
	gid_t gid_t_type;
	old_uid_t old_uid_t_type;
	old_gid_t old_gid_t_type;
	loff_t loff_t_type;
	unsigned long * unsigned_long_ptr_type;
	compat_long_t compat_long_t_type;
	compat_ulong_t * compat_ulong_t_ptr_type;
	u32 * u32_ptr_type;
	struct stat64 * struct_stat64_ptr_type;
	__u32 __u32_type;
	struct sockaddr * struct_sockaddr_ptr_type;
	struct timeval32 * struct_timeval32_ptr_type;
	fd_set * fd_set_ptr_type;
	loff_t * loff_t_ptr_type;
	unsigned unsigned_type;
	compat_uptr_t * compat_uptr_t_ptr_type;
	struct io_event * struct_io_event_ptr_type;
	struct __kernel_itimerspec * struct___kernel_itimerspec_ptr_type;
	struct old_itimerspec32 * struct_old_itimerspec32_ptr_type;
	mqd_t mqd_t_type;
	timer_t timer_t_type;
	struct old_timeval32 * struct_old_timeval32_ptr_type;
	compat_pid_t compat_pid_t_type;
	struct compat_siginfo * struct_compat_siginfo_ptr_type;
	gid_t * gid_t_ptr_type;
	old_gid_t * old_gid_t_ptr_type;
	struct timezone * struct_timezone_ptr_type;
	struct compat_sigaction * struct_compat_sigaction_ptr_type;
	struct compat_statfs64 * struct_compat_statfs64_ptr_type;
	struct stat64_emu31 * struct_stat64_emu31_ptr_type;
	struct __kernel_timex * struct___kernel_timex_ptr_type;
	aio_context_t aio_context_t_type;
	struct epoll_event * struct_epoll_event_ptr_type;
	struct pollfd * struct_pollfd_ptr_type;
	struct compat_stat * struct_compat_stat_ptr_type;
	rwf_t rwf_t_type;
	compat_uptr_t compat_uptr_t_type;
	struct osf_stat * struct_osf_stat_ptr_type;
	struct ucontext * struct_ucontext_ptr_type;
	uintptr_t uintptr_t_type;
	u64 * u64_ptr_type;
	compat_aio_context_t compat_aio_context_t_type;
	__s32 __s32_type;
	compat_off_t compat_off_t_type;
	struct __old_kernel_stat * struct___old_kernel_stat_ptr_type;
	struct compat_mq_attr * struct_compat_mq_attr_ptr_type;
	key_t key_t_type;
	struct sembuf * struct_sembuf_ptr_type;
	struct compat_rusage * struct_compat_rusage_ptr_type;
	uid_t * uid_t_ptr_type;
	old_uid_t * old_uid_t_ptr_type;
	struct sched_param * struct_sched_param_ptr_type;
	struct old_itimerval32 * struct_old_itimerval32_ptr_type;
	struct mmsghdr * struct_mmsghdr_ptr_type;
	struct osf_statfs * struct_osf_statfs_ptr_type;
	struct osf_statfs64 * struct_osf_statfs64_ptr_type;
	struct sigstack * struct_sigstack_ptr_type;
	struct rusage32 * struct_rusage32_ptr_type;
	struct osf_sigaction * struct_osf_sigaction_ptr_type;
	struct user_desc * struct_user_desc_ptr_type;
	u64 u64_type;
	struct compat_old_sigaction * struct_compat_old_sigaction_ptr_type;
	__u32 * __u32_ptr_type;
	struct mmap_arg_struct_emu31 * struct_mmap_arg_struct_emu31_ptr_type;
	struct old_sigaction * struct_old_sigaction_ptr_type;
	utrap_handler_t utrap_handler_t_type;
	utrap_handler_t * utrap_handler_t_ptr_type;
	struct __compat_aio_sigset * struct___compat_aio_sigset_ptr_type;
	struct file_handle * struct_file_handle_ptr_type;
	struct mnt_id_req * struct_mnt_id_req_ptr_type;
	sigset_t * sigset_t_ptr_type;
	struct compat_statfs * struct_compat_statfs_ptr_type;
	struct __kernel_old_timeval * struct___kernel_old_timeval_ptr_type;
	struct xattr_args * struct_xattr_args_ptr_type;
	qid_t qid_t_type;
	unsigned int * unsigned_int_ptr_type;
	struct compat_sigevent * struct_compat_sigevent_ptr_type;
	compat_ssize_t compat_ssize_t_type;
	cap_user_header_t cap_user_header_t_type;
	cap_user_data_t cap_user_data_t_type;
	old_sigset_t * old_sigset_t_ptr_type;
	siginfo_t * siginfo_t_ptr_type;
	compat_stack_t * compat_stack_t_ptr_type;
	struct compat_rlimit * struct_compat_rlimit_ptr_type;
	struct rlimit64 * struct_rlimit64_ptr_type;
	unsigned * unsigned_ptr_type;
	struct futex_waitv * struct_futex_waitv_ptr_type;
	struct sched_attr * struct_sched_attr_ptr_type;
	struct old_timex32 * struct_old_timex32_ptr_type;
	__kernel_old_time_t * __kernel_old_time_t_ptr_type;
	old_time32_t * old_time32_t_ptr_type;
	struct user_msghdr * struct_user_msghdr_ptr_type;
	struct lsm_ctx * struct_lsm_ctx_ptr_type;
	key_serial_t key_serial_t_type;
	struct osf_dirent * struct_osf_dirent_ptr_type;
	long * long_ptr_type;
	enum pl_code enum_pl_code_type;
	union pl_args * union_pl_args_ptr_type;
	struct timex32 * struct_timex32_ptr_type;
	old_sigset_t old_sigset_t_type;
	off_t off_t_type;
	struct rtas_args * struct_rtas_args_ptr_type;
	struct sig_dbg_op * struct_sig_dbg_op_ptr_type;
	struct riscv_hwprobe * struct_riscv_hwprobe_ptr_type;
	uint uint_type;
	s32 s32_type;
	struct fadvise64_64_args * struct_fadvise64_64_args_ptr_type;
	struct gs_cb * struct_gs_cb_ptr_type;
	utrap_entry_t utrap_entry_t_type;
	struct mmap_arg_struct32 * struct_mmap_arg_struct32_ptr_type;
	struct vm86_struct * struct_vm86_struct_ptr_type;
	struct iocb * struct_iocb_ptr_type;
	struct __aio_sigset * struct___aio_sigset_ptr_type;
	struct mount_attr * struct_mount_attr_ptr_type;
	struct statmount * struct_statmount_ptr_type;
	struct open_how * struct_open_how_ptr_type;
	struct compat_old_linux_dirent * struct_compat_old_linux_dirent_ptr_type;
	struct compat_linux_dirent * struct_compat_linux_dirent_ptr_type;
	struct linux_dirent64 * struct_linux_dirent64_ptr_type;
	struct compat_sel_arg_struct * struct_compat_sel_arg_struct_ptr_type;
	struct statx * struct_statx_ptr_type;
	struct compat_ustat * struct_compat_ustat_ptr_type;
	struct utimbuf * struct_utimbuf_ptr_type;
	struct old_utimbuf32 * struct_old_utimbuf32_ptr_type;
	compat_off_t * compat_off_t_ptr_type;
	compat_loff_t * compat_loff_t_ptr_type;
	__u64 __u64_type;
	struct io_uring_params * struct_io_uring_params_ptr_type;
	compat_mode_t compat_mode_t_type;
	compat_uint_t * compat_uint_t_ptr_type;
	struct clone_args * struct_clone_args_ptr_type;
	struct compat_kexec_segment * struct_compat_kexec_segment_ptr_type;
	struct rseq * struct_rseq_ptr_type;
	compat_old_sigset_t * compat_old_sigset_t_ptr_type;
	__sighandler_t __sighandler_t_type;
	struct compat_tms * struct_compat_tms_ptr_type;
	struct new_utsname * struct_new_utsname_ptr_type;
	struct old_utsname * struct_old_utsname_ptr_type;
	struct oldold_utsname * struct_oldold_utsname_ptr_type;
	struct rlimit * struct_rlimit_ptr_type;
	struct getcpu_cache * struct_getcpu_cache_ptr_type;
	struct compat_sysinfo * struct_compat_sysinfo_ptr_type;
	union bpf_attr * union_bpf_attr_ptr_type;
	struct perf_event_attr * struct_perf_event_attr_ptr_type;
	struct compat_robust_list_head * struct_compat_robust_list_head_ptr_type;
	compat_size_t * compat_size_t_ptr_type;
	timer_t * timer_t_ptr_type;
	struct cachestat_range * struct_cachestat_range_ptr_type;
	struct cachestat * struct_cachestat_ptr_type;
	unsigned char * unsigned_char_ptr_type;
	struct mmap_arg_struct * struct_mmap_arg_struct_ptr_type;
	struct compat_mmsghdr * struct_compat_mmsghdr_ptr_type;
	struct landlock_ruleset_attr * struct_landlock_ruleset_attr_ptr_type;
	enum landlock_rule_type enum_landlock_rule_type_type;
} SyscallParam;

#define INT_TYPE 0
#define UNSIGNED_LONG_TYPE 1
#define UNSIGNED_INT_TYPE 2
#define CHAR_PTR_TYPE 3
#define U32_TYPE 4
#define SIZE_T_TYPE 5
#define VOID_PTR_TYPE 6
#define PID_T_TYPE 7
#define COMPAT_SIZE_T_TYPE 8
#define STRUCT___KERNEL_TIMESPEC_PTR_TYPE 9
#define INT_PTR_TYPE 10
#define STRUCT_OLD_TIMESPEC32_PTR_TYPE 11
#define STRUCT_IOVEC_PTR_TYPE 12
#define CLOCKID_T_TYPE 13
#define COMPAT_ULONG_T_TYPE 14
#define LONG_TYPE 15
#define UMODE_T_TYPE 16
#define COMPAT_SIGSET_T_PTR_TYPE 17
#define UID_T_TYPE 18
#define GID_T_TYPE 19
#define OLD_UID_T_TYPE 20
#define OLD_GID_T_TYPE 21
#define LOFF_T_TYPE 22
#define UNSIGNED_LONG_PTR_TYPE 23
#define COMPAT_LONG_T_TYPE 24
#define COMPAT_ULONG_T_PTR_TYPE 25
#define U32_PTR_TYPE 26
#define STRUCT_STAT64_PTR_TYPE 27
#define __U32_TYPE 28
#define STRUCT_SOCKADDR_PTR_TYPE 29
#define STRUCT_TIMEVAL32_PTR_TYPE 30
#define FD_SET_PTR_TYPE 31
#define LOFF_T_PTR_TYPE 32
#define UNSIGNED_TYPE 33
#define COMPAT_UPTR_T_PTR_TYPE 34
#define STRUCT_IO_EVENT_PTR_TYPE 35
#define STRUCT___KERNEL_ITIMERSPEC_PTR_TYPE 36
#define STRUCT_OLD_ITIMERSPEC32_PTR_TYPE 37
#define MQD_T_TYPE 38
#define TIMER_T_TYPE 39
#define STRUCT_OLD_TIMEVAL32_PTR_TYPE 40
#define COMPAT_PID_T_TYPE 41
#define STRUCT_COMPAT_SIGINFO_PTR_TYPE 42
#define GID_T_PTR_TYPE 43
#define OLD_GID_T_PTR_TYPE 44
#define STRUCT_TIMEZONE_PTR_TYPE 45
#define STRUCT_COMPAT_SIGACTION_PTR_TYPE 46
#define STRUCT_COMPAT_STATFS64_PTR_TYPE 47
#define STRUCT_STAT64_EMU31_PTR_TYPE 48
#define STRUCT___KERNEL_TIMEX_PTR_TYPE 49
#define AIO_CONTEXT_T_TYPE 50
#define STRUCT_EPOLL_EVENT_PTR_TYPE 51
#define STRUCT_POLLFD_PTR_TYPE 52
#define STRUCT_COMPAT_STAT_PTR_TYPE 53
#define RWF_T_TYPE 54
#define COMPAT_UPTR_T_TYPE 55
#define STRUCT_OSF_STAT_PTR_TYPE 56
#define STRUCT_UCONTEXT_PTR_TYPE 57
#define UINTPTR_T_TYPE 58
#define U64_PTR_TYPE 59
#define COMPAT_AIO_CONTEXT_T_TYPE 60
#define __S32_TYPE 61
#define COMPAT_OFF_T_TYPE 62
#define STRUCT___OLD_KERNEL_STAT_PTR_TYPE 63
#define STRUCT_COMPAT_MQ_ATTR_PTR_TYPE 64
#define KEY_T_TYPE 65
#define STRUCT_SEMBUF_PTR_TYPE 66
#define STRUCT_COMPAT_RUSAGE_PTR_TYPE 67
#define UID_T_PTR_TYPE 68
#define OLD_UID_T_PTR_TYPE 69
#define STRUCT_SCHED_PARAM_PTR_TYPE 70
#define STRUCT_OLD_ITIMERVAL32_PTR_TYPE 71
#define STRUCT_MMSGHDR_PTR_TYPE 72
#define STRUCT_OSF_STATFS_PTR_TYPE 73
#define STRUCT_OSF_STATFS64_PTR_TYPE 74
#define STRUCT_SIGSTACK_PTR_TYPE 75
#define STRUCT_RUSAGE32_PTR_TYPE 76
#define STRUCT_OSF_SIGACTION_PTR_TYPE 77
#define STRUCT_USER_DESC_PTR_TYPE 78
#define U64_TYPE 79
#define STRUCT_COMPAT_OLD_SIGACTION_PTR_TYPE 80
#define __U32_PTR_TYPE 81
#define STRUCT_MMAP_ARG_STRUCT_EMU31_PTR_TYPE 82
#define STRUCT_OLD_SIGACTION_PTR_TYPE 83
#define UTRAP_HANDLER_T_TYPE 84
#define UTRAP_HANDLER_T_PTR_TYPE 85
#define STRUCT___COMPAT_AIO_SIGSET_PTR_TYPE 86
#define STRUCT_FILE_HANDLE_PTR_TYPE 87
#define STRUCT_MNT_ID_REQ_PTR_TYPE 88
#define SIGSET_T_PTR_TYPE 89
#define STRUCT_COMPAT_STATFS_PTR_TYPE 90
#define STRUCT___KERNEL_OLD_TIMEVAL_PTR_TYPE 91
#define STRUCT_XATTR_ARGS_PTR_TYPE 92
#define QID_T_TYPE 93
#define UNSIGNED_INT_PTR_TYPE 94
#define STRUCT_COMPAT_SIGEVENT_PTR_TYPE 95
#define COMPAT_SSIZE_T_TYPE 96
#define CAP_USER_HEADER_T_TYPE 97
#define CAP_USER_DATA_T_TYPE 98
#define OLD_SIGSET_T_PTR_TYPE 99
#define SIGINFO_T_PTR_TYPE 100
#define COMPAT_STACK_T_PTR_TYPE 101
#define STRUCT_COMPAT_RLIMIT_PTR_TYPE 102
#define STRUCT_RLIMIT64_PTR_TYPE 103
#define UNSIGNED_PTR_TYPE 104
#define STRUCT_FUTEX_WAITV_PTR_TYPE 105
#define STRUCT_SCHED_ATTR_PTR_TYPE 106
#define STRUCT_OLD_TIMEX32_PTR_TYPE 107
#define __KERNEL_OLD_TIME_T_PTR_TYPE 108
#define OLD_TIME32_T_PTR_TYPE 109
#define STRUCT_USER_MSGHDR_PTR_TYPE 110
#define STRUCT_LSM_CTX_PTR_TYPE 111
#define KEY_SERIAL_T_TYPE 112
#define STRUCT_OSF_DIRENT_PTR_TYPE 113
#define LONG_PTR_TYPE 114
#define ENUM_PL_CODE_TYPE 115
#define UNION_PL_ARGS_PTR_TYPE 116
#define STRUCT_TIMEX32_PTR_TYPE 117
#define OLD_SIGSET_T_TYPE 118
#define OFF_T_TYPE 119
#define STRUCT_RTAS_ARGS_PTR_TYPE 120
#define STRUCT_SIG_DBG_OP_PTR_TYPE 121
#define STRUCT_RISCV_HWPROBE_PTR_TYPE 122
#define UINT_TYPE 123
#define S32_TYPE 124
#define STRUCT_FADVISE64_64_ARGS_PTR_TYPE 125
#define STRUCT_GS_CB_PTR_TYPE 126
#define UTRAP_ENTRY_T_TYPE 127
#define STRUCT_MMAP_ARG_STRUCT32_PTR_TYPE 128
#define STRUCT_VM86_STRUCT_PTR_TYPE 129
#define STRUCT_IOCB_PTR_TYPE 130
#define STRUCT___AIO_SIGSET_PTR_TYPE 131
#define STRUCT_MOUNT_ATTR_PTR_TYPE 132
#define STRUCT_STATMOUNT_PTR_TYPE 133
#define STRUCT_OPEN_HOW_PTR_TYPE 134
#define STRUCT_COMPAT_OLD_LINUX_DIRENT_PTR_TYPE 135
#define STRUCT_COMPAT_LINUX_DIRENT_PTR_TYPE 136
#define STRUCT_LINUX_DIRENT64_PTR_TYPE 137
#define STRUCT_COMPAT_SEL_ARG_STRUCT_PTR_TYPE 138
#define STRUCT_STATX_PTR_TYPE 139
#define STRUCT_COMPAT_USTAT_PTR_TYPE 140
#define STRUCT_UTIMBUF_PTR_TYPE 141
#define STRUCT_OLD_UTIMBUF32_PTR_TYPE 142
#define COMPAT_OFF_T_PTR_TYPE 143
#define COMPAT_LOFF_T_PTR_TYPE 144
#define __U64_TYPE 145
#define STRUCT_IO_URING_PARAMS_PTR_TYPE 146
#define COMPAT_MODE_T_TYPE 147
#define COMPAT_UINT_T_PTR_TYPE 148
#define STRUCT_CLONE_ARGS_PTR_TYPE 149
#define STRUCT_COMPAT_KEXEC_SEGMENT_PTR_TYPE 150
#define STRUCT_RSEQ_PTR_TYPE 151
#define COMPAT_OLD_SIGSET_T_PTR_TYPE 152
#define __SIGHANDLER_T_TYPE 153
#define STRUCT_COMPAT_TMS_PTR_TYPE 154
#define STRUCT_NEW_UTSNAME_PTR_TYPE 155
#define STRUCT_OLD_UTSNAME_PTR_TYPE 156
#define STRUCT_OLDOLD_UTSNAME_PTR_TYPE 157
#define STRUCT_RLIMIT_PTR_TYPE 158
#define STRUCT_GETCPU_CACHE_PTR_TYPE 159
#define STRUCT_COMPAT_SYSINFO_PTR_TYPE 160
#define UNION_BPF_ATTR_PTR_TYPE 161
#define STRUCT_PERF_EVENT_ATTR_PTR_TYPE 162
#define STRUCT_COMPAT_ROBUST_LIST_HEAD_PTR_TYPE 163
#define COMPAT_SIZE_T_PTR_TYPE 164
#define TIMER_T_PTR_TYPE 165
#define STRUCT_CACHESTAT_RANGE_PTR_TYPE 166
#define STRUCT_CACHESTAT_PTR_TYPE 167
#define UNSIGNED_CHAR_PTR_TYPE 168
#define STRUCT_MMAP_ARG_STRUCT_PTR_TYPE 169
#define STRUCT_COMPAT_MMSGHDR_PTR_TYPE 170
#define STRUCT_LANDLOCK_RULESET_ATTR_PTR_TYPE 171
#define ENUM_LANDLOCK_RULE_TYPE_TYPE 172
void* fetch_param_variant(SyscallParam *src, int param_type) {
	switch (param_type) {
		case INT_TYPE: return &src->int_type;
		case UNSIGNED_LONG_TYPE: return &src->unsigned_long_type;
		case UNSIGNED_INT_TYPE: return &src->unsigned_int_type;
		case CHAR_PTR_TYPE: return &src->char_ptr_type;
		case U32_TYPE: return &src->u32_type;
		case SIZE_T_TYPE: return &src->size_t_type;
		case VOID_PTR_TYPE: return &src->void_ptr_type;
		case PID_T_TYPE: return &src->pid_t_type;
		case COMPAT_SIZE_T_TYPE: return &src->compat_size_t_type;
		case STRUCT___KERNEL_TIMESPEC_PTR_TYPE: return &src->struct___kernel_timespec_ptr_type;
		case INT_PTR_TYPE: return &src->int_ptr_type;
		case STRUCT_OLD_TIMESPEC32_PTR_TYPE: return &src->struct_old_timespec32_ptr_type;
		case STRUCT_IOVEC_PTR_TYPE: return &src->struct_iovec_ptr_type;
		case CLOCKID_T_TYPE: return &src->clockid_t_type;
		case COMPAT_ULONG_T_TYPE: return &src->compat_ulong_t_type;
		case LONG_TYPE: return &src->long_type;
		case UMODE_T_TYPE: return &src->umode_t_type;
		case COMPAT_SIGSET_T_PTR_TYPE: return &src->compat_sigset_t_ptr_type;
		case UID_T_TYPE: return &src->uid_t_type;
		case GID_T_TYPE: return &src->gid_t_type;
		case OLD_UID_T_TYPE: return &src->old_uid_t_type;
		case OLD_GID_T_TYPE: return &src->old_gid_t_type;
		case LOFF_T_TYPE: return &src->loff_t_type;
		case UNSIGNED_LONG_PTR_TYPE: return &src->unsigned_long_ptr_type;
		case COMPAT_LONG_T_TYPE: return &src->compat_long_t_type;
		case COMPAT_ULONG_T_PTR_TYPE: return &src->compat_ulong_t_ptr_type;
		case U32_PTR_TYPE: return &src->u32_ptr_type;
		case STRUCT_STAT64_PTR_TYPE: return &src->struct_stat64_ptr_type;
		case __U32_TYPE: return &src->__u32_type;
		case STRUCT_SOCKADDR_PTR_TYPE: return &src->struct_sockaddr_ptr_type;
		case STRUCT_TIMEVAL32_PTR_TYPE: return &src->struct_timeval32_ptr_type;
		case FD_SET_PTR_TYPE: return &src->fd_set_ptr_type;
		case LOFF_T_PTR_TYPE: return &src->loff_t_ptr_type;
		case UNSIGNED_TYPE: return &src->unsigned_type;
		case COMPAT_UPTR_T_PTR_TYPE: return &src->compat_uptr_t_ptr_type;
		case STRUCT_IO_EVENT_PTR_TYPE: return &src->struct_io_event_ptr_type;
		case STRUCT___KERNEL_ITIMERSPEC_PTR_TYPE: return &src->struct___kernel_itimerspec_ptr_type;
		case STRUCT_OLD_ITIMERSPEC32_PTR_TYPE: return &src->struct_old_itimerspec32_ptr_type;
		case MQD_T_TYPE: return &src->mqd_t_type;
		case TIMER_T_TYPE: return &src->timer_t_type;
		case STRUCT_OLD_TIMEVAL32_PTR_TYPE: return &src->struct_old_timeval32_ptr_type;
		case COMPAT_PID_T_TYPE: return &src->compat_pid_t_type;
		case STRUCT_COMPAT_SIGINFO_PTR_TYPE: return &src->struct_compat_siginfo_ptr_type;
		case GID_T_PTR_TYPE: return &src->gid_t_ptr_type;
		case OLD_GID_T_PTR_TYPE: return &src->old_gid_t_ptr_type;
		case STRUCT_TIMEZONE_PTR_TYPE: return &src->struct_timezone_ptr_type;
		case STRUCT_COMPAT_SIGACTION_PTR_TYPE: return &src->struct_compat_sigaction_ptr_type;
		case STRUCT_COMPAT_STATFS64_PTR_TYPE: return &src->struct_compat_statfs64_ptr_type;
		case STRUCT_STAT64_EMU31_PTR_TYPE: return &src->struct_stat64_emu31_ptr_type;
		case STRUCT___KERNEL_TIMEX_PTR_TYPE: return &src->struct___kernel_timex_ptr_type;
		case AIO_CONTEXT_T_TYPE: return &src->aio_context_t_type;
		case STRUCT_EPOLL_EVENT_PTR_TYPE: return &src->struct_epoll_event_ptr_type;
		case STRUCT_POLLFD_PTR_TYPE: return &src->struct_pollfd_ptr_type;
		case STRUCT_COMPAT_STAT_PTR_TYPE: return &src->struct_compat_stat_ptr_type;
		case RWF_T_TYPE: return &src->rwf_t_type;
		case COMPAT_UPTR_T_TYPE: return &src->compat_uptr_t_type;
		case STRUCT_OSF_STAT_PTR_TYPE: return &src->struct_osf_stat_ptr_type;
		case STRUCT_UCONTEXT_PTR_TYPE: return &src->struct_ucontext_ptr_type;
		case UINTPTR_T_TYPE: return &src->uintptr_t_type;
		case U64_PTR_TYPE: return &src->u64_ptr_type;
		case COMPAT_AIO_CONTEXT_T_TYPE: return &src->compat_aio_context_t_type;
		case __S32_TYPE: return &src->__s32_type;
		case COMPAT_OFF_T_TYPE: return &src->compat_off_t_type;
		case STRUCT___OLD_KERNEL_STAT_PTR_TYPE: return &src->struct___old_kernel_stat_ptr_type;
		case STRUCT_COMPAT_MQ_ATTR_PTR_TYPE: return &src->struct_compat_mq_attr_ptr_type;
		case KEY_T_TYPE: return &src->key_t_type;
		case STRUCT_SEMBUF_PTR_TYPE: return &src->struct_sembuf_ptr_type;
		case STRUCT_COMPAT_RUSAGE_PTR_TYPE: return &src->struct_compat_rusage_ptr_type;
		case UID_T_PTR_TYPE: return &src->uid_t_ptr_type;
		case OLD_UID_T_PTR_TYPE: return &src->old_uid_t_ptr_type;
		case STRUCT_SCHED_PARAM_PTR_TYPE: return &src->struct_sched_param_ptr_type;
		case STRUCT_OLD_ITIMERVAL32_PTR_TYPE: return &src->struct_old_itimerval32_ptr_type;
		case STRUCT_MMSGHDR_PTR_TYPE: return &src->struct_mmsghdr_ptr_type;
		case STRUCT_OSF_STATFS_PTR_TYPE: return &src->struct_osf_statfs_ptr_type;
		case STRUCT_OSF_STATFS64_PTR_TYPE: return &src->struct_osf_statfs64_ptr_type;
		case STRUCT_SIGSTACK_PTR_TYPE: return &src->struct_sigstack_ptr_type;
		case STRUCT_RUSAGE32_PTR_TYPE: return &src->struct_rusage32_ptr_type;
		case STRUCT_OSF_SIGACTION_PTR_TYPE: return &src->struct_osf_sigaction_ptr_type;
		case STRUCT_USER_DESC_PTR_TYPE: return &src->struct_user_desc_ptr_type;
		case U64_TYPE: return &src->u64_type;
		case STRUCT_COMPAT_OLD_SIGACTION_PTR_TYPE: return &src->struct_compat_old_sigaction_ptr_type;
		case __U32_PTR_TYPE: return &src->__u32_ptr_type;
		case STRUCT_MMAP_ARG_STRUCT_EMU31_PTR_TYPE: return &src->struct_mmap_arg_struct_emu31_ptr_type;
		case STRUCT_OLD_SIGACTION_PTR_TYPE: return &src->struct_old_sigaction_ptr_type;
		case UTRAP_HANDLER_T_TYPE: return &src->utrap_handler_t_type;
		case UTRAP_HANDLER_T_PTR_TYPE: return &src->utrap_handler_t_ptr_type;
		case STRUCT___COMPAT_AIO_SIGSET_PTR_TYPE: return &src->struct___compat_aio_sigset_ptr_type;
		case STRUCT_FILE_HANDLE_PTR_TYPE: return &src->struct_file_handle_ptr_type;
		case STRUCT_MNT_ID_REQ_PTR_TYPE: return &src->struct_mnt_id_req_ptr_type;
		case SIGSET_T_PTR_TYPE: return &src->sigset_t_ptr_type;
		case STRUCT_COMPAT_STATFS_PTR_TYPE: return &src->struct_compat_statfs_ptr_type;
		case STRUCT___KERNEL_OLD_TIMEVAL_PTR_TYPE: return &src->struct___kernel_old_timeval_ptr_type;
		case STRUCT_XATTR_ARGS_PTR_TYPE: return &src->struct_xattr_args_ptr_type;
		case QID_T_TYPE: return &src->qid_t_type;
		case UNSIGNED_INT_PTR_TYPE: return &src->unsigned_int_ptr_type;
		case STRUCT_COMPAT_SIGEVENT_PTR_TYPE: return &src->struct_compat_sigevent_ptr_type;
		case COMPAT_SSIZE_T_TYPE: return &src->compat_ssize_t_type;
		case CAP_USER_HEADER_T_TYPE: return &src->cap_user_header_t_type;
		case CAP_USER_DATA_T_TYPE: return &src->cap_user_data_t_type;
		case OLD_SIGSET_T_PTR_TYPE: return &src->old_sigset_t_ptr_type;
		case SIGINFO_T_PTR_TYPE: return &src->siginfo_t_ptr_type;
		case COMPAT_STACK_T_PTR_TYPE: return &src->compat_stack_t_ptr_type;
		case STRUCT_COMPAT_RLIMIT_PTR_TYPE: return &src->struct_compat_rlimit_ptr_type;
		case STRUCT_RLIMIT64_PTR_TYPE: return &src->struct_rlimit64_ptr_type;
		case UNSIGNED_PTR_TYPE: return &src->unsigned_ptr_type;
		case STRUCT_FUTEX_WAITV_PTR_TYPE: return &src->struct_futex_waitv_ptr_type;
		case STRUCT_SCHED_ATTR_PTR_TYPE: return &src->struct_sched_attr_ptr_type;
		case STRUCT_OLD_TIMEX32_PTR_TYPE: return &src->struct_old_timex32_ptr_type;
		case __KERNEL_OLD_TIME_T_PTR_TYPE: return &src->__kernel_old_time_t_ptr_type;
		case OLD_TIME32_T_PTR_TYPE: return &src->old_time32_t_ptr_type;
		case STRUCT_USER_MSGHDR_PTR_TYPE: return &src->struct_user_msghdr_ptr_type;
		case STRUCT_LSM_CTX_PTR_TYPE: return &src->struct_lsm_ctx_ptr_type;
		case KEY_SERIAL_T_TYPE: return &src->key_serial_t_type;
		case STRUCT_OSF_DIRENT_PTR_TYPE: return &src->struct_osf_dirent_ptr_type;
		case LONG_PTR_TYPE: return &src->long_ptr_type;
		case ENUM_PL_CODE_TYPE: return &src->enum_pl_code_type;
		case UNION_PL_ARGS_PTR_TYPE: return &src->union_pl_args_ptr_type;
		case STRUCT_TIMEX32_PTR_TYPE: return &src->struct_timex32_ptr_type;
		case OLD_SIGSET_T_TYPE: return &src->old_sigset_t_type;
		case OFF_T_TYPE: return &src->off_t_type;
		case STRUCT_RTAS_ARGS_PTR_TYPE: return &src->struct_rtas_args_ptr_type;
		case STRUCT_SIG_DBG_OP_PTR_TYPE: return &src->struct_sig_dbg_op_ptr_type;
		case STRUCT_RISCV_HWPROBE_PTR_TYPE: return &src->struct_riscv_hwprobe_ptr_type;
		case UINT_TYPE: return &src->uint_type;
		case S32_TYPE: return &src->s32_type;
		case STRUCT_FADVISE64_64_ARGS_PTR_TYPE: return &src->struct_fadvise64_64_args_ptr_type;
		case STRUCT_GS_CB_PTR_TYPE: return &src->struct_gs_cb_ptr_type;
		case UTRAP_ENTRY_T_TYPE: return &src->utrap_entry_t_type;
		case STRUCT_MMAP_ARG_STRUCT32_PTR_TYPE: return &src->struct_mmap_arg_struct32_ptr_type;
		case STRUCT_VM86_STRUCT_PTR_TYPE: return &src->struct_vm86_struct_ptr_type;
		case STRUCT_IOCB_PTR_TYPE: return &src->struct_iocb_ptr_type;
		case STRUCT___AIO_SIGSET_PTR_TYPE: return &src->struct___aio_sigset_ptr_type;
		case STRUCT_MOUNT_ATTR_PTR_TYPE: return &src->struct_mount_attr_ptr_type;
		case STRUCT_STATMOUNT_PTR_TYPE: return &src->struct_statmount_ptr_type;
		case STRUCT_OPEN_HOW_PTR_TYPE: return &src->struct_open_how_ptr_type;
		case STRUCT_COMPAT_OLD_LINUX_DIRENT_PTR_TYPE: return &src->struct_compat_old_linux_dirent_ptr_type;
		case STRUCT_COMPAT_LINUX_DIRENT_PTR_TYPE: return &src->struct_compat_linux_dirent_ptr_type;
		case STRUCT_LINUX_DIRENT64_PTR_TYPE: return &src->struct_linux_dirent64_ptr_type;
		case STRUCT_COMPAT_SEL_ARG_STRUCT_PTR_TYPE: return &src->struct_compat_sel_arg_struct_ptr_type;
		case STRUCT_STATX_PTR_TYPE: return &src->struct_statx_ptr_type;
		case STRUCT_COMPAT_USTAT_PTR_TYPE: return &src->struct_compat_ustat_ptr_type;
		case STRUCT_UTIMBUF_PTR_TYPE: return &src->struct_utimbuf_ptr_type;
		case STRUCT_OLD_UTIMBUF32_PTR_TYPE: return &src->struct_old_utimbuf32_ptr_type;
		case COMPAT_OFF_T_PTR_TYPE: return &src->compat_off_t_ptr_type;
		case COMPAT_LOFF_T_PTR_TYPE: return &src->compat_loff_t_ptr_type;
		case __U64_TYPE: return &src->__u64_type;
		case STRUCT_IO_URING_PARAMS_PTR_TYPE: return &src->struct_io_uring_params_ptr_type;
		case COMPAT_MODE_T_TYPE: return &src->compat_mode_t_type;
		case COMPAT_UINT_T_PTR_TYPE: return &src->compat_uint_t_ptr_type;
		case STRUCT_CLONE_ARGS_PTR_TYPE: return &src->struct_clone_args_ptr_type;
		case STRUCT_COMPAT_KEXEC_SEGMENT_PTR_TYPE: return &src->struct_compat_kexec_segment_ptr_type;
		case STRUCT_RSEQ_PTR_TYPE: return &src->struct_rseq_ptr_type;
		case COMPAT_OLD_SIGSET_T_PTR_TYPE: return &src->compat_old_sigset_t_ptr_type;
		case __SIGHANDLER_T_TYPE: return &src->__sighandler_t_type;
		case STRUCT_COMPAT_TMS_PTR_TYPE: return &src->struct_compat_tms_ptr_type;
		case STRUCT_NEW_UTSNAME_PTR_TYPE: return &src->struct_new_utsname_ptr_type;
		case STRUCT_OLD_UTSNAME_PTR_TYPE: return &src->struct_old_utsname_ptr_type;
		case STRUCT_OLDOLD_UTSNAME_PTR_TYPE: return &src->struct_oldold_utsname_ptr_type;
		case STRUCT_RLIMIT_PTR_TYPE: return &src->struct_rlimit_ptr_type;
		case STRUCT_GETCPU_CACHE_PTR_TYPE: return &src->struct_getcpu_cache_ptr_type;
		case STRUCT_COMPAT_SYSINFO_PTR_TYPE: return &src->struct_compat_sysinfo_ptr_type;
		case UNION_BPF_ATTR_PTR_TYPE: return &src->union_bpf_attr_ptr_type;
		case STRUCT_PERF_EVENT_ATTR_PTR_TYPE: return &src->struct_perf_event_attr_ptr_type;
		case STRUCT_COMPAT_ROBUST_LIST_HEAD_PTR_TYPE: return &src->struct_compat_robust_list_head_ptr_type;
		case COMPAT_SIZE_T_PTR_TYPE: return &src->compat_size_t_ptr_type;
		case TIMER_T_PTR_TYPE: return &src->timer_t_ptr_type;
		case STRUCT_CACHESTAT_RANGE_PTR_TYPE: return &src->struct_cachestat_range_ptr_type;
		case STRUCT_CACHESTAT_PTR_TYPE: return &src->struct_cachestat_ptr_type;
		case UNSIGNED_CHAR_PTR_TYPE: return &src->unsigned_char_ptr_type;
		case STRUCT_MMAP_ARG_STRUCT_PTR_TYPE: return &src->struct_mmap_arg_struct_ptr_type;
		case STRUCT_COMPAT_MMSGHDR_PTR_TYPE: return &src->struct_compat_mmsghdr_ptr_type;
		case STRUCT_LANDLOCK_RULESET_ATTR_PTR_TYPE: return &src->struct_landlock_ruleset_attr_ptr_type;
		case ENUM_LANDLOCK_RULE_TYPE_TYPE: return &src->enum_landlock_rule_type_type;
		default: return &src->char_ptr_type;
	}
	return &src->char_ptr_type;

}
