#include "rscaller.h"

#include <linux/syscalls.h>
#include <linux/dirent.h>
#include <linux/slab.h>
#include <linux/version.h> 

#include <linux/module.h>
#include <linux/sched.h>
#include <linux/mm.h>

#include <linux/fs.h>
#include <linux/nsproxy.h>
#include "misssing_defs.h"
#include <linux/init.h>
#include <linux/kernel.h> /* min */
#include <linux/proc_fs.h>
#include <linux/uaccess.h> /* copy_from_user, copy_to_user */
#include <asm/io.h>        /* virt_to_phys */
#include <linux/slab.h>

#include <khook/engine.h>
#include <linux/kprobes.h>


#if IS_ENABLED(CONFIG_X86) || IS_ENABLED(CONFIG_X86_64)
unsigned long cr0;
#elif IS_ENABLED(CONFIG_ARM64)
void (*update_mapping_prot)(phys_addr_t phys, unsigned long virt, phys_addr_t size, pgprot_t prot);
unsigned long start_rodata;
unsigned long init_begin;
#define section_size init_begin - start_rodata
#endif


#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)
#define HAVE_PROC_OPS
#endif

/* vm_flags_set/vm_flags_clear: introduced in 6.3 (vm_flags became const).
 * Provide shim for older kernels. */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 3, 0)
#define vm_flags_set(vma, flags)   ((vma)->vm_flags |= (flags))
#define vm_flags_clear(vma, flags) ((vma)->vm_flags &= ~(flags))
#endif

/* Cgroup namespace inode number of the target container (--image mode).
 * Written by rscaller-run after starting the container.
 * 0 = disabled. */
static unsigned long container_cgns_inum = 0;
module_param(container_cgns_inum, ulong, 0644);
MODULE_PARM_DESC(container_cgns_inum, "Cgroup namespace inode of the container to intercept");

/* Host-absolute path prefix of binaries to intercept (--progs-folder mode).
 * e.g. /var/lib/docker/overlay2/HASH/merged  or  /opt/my-progs
 * Empty string = disabled. */
static char remote_progs_folder[512] = "";
module_param_string(remote_progs_folder, remote_progs_folder, sizeof(remote_progs_folder), 0644);
MODULE_PARM_DESC(remote_progs_folder, "Host path prefix of binaries whose syscalls should be forwarded");

/* Set to 1 when rsclient opens /proc/rscaller; 0 when it closes.
 * Intercept only while a client is actively connected to avoid blocking
 * all userspace processes when no relay is running. */
static atomic_t rsclient_active = ATOMIC_INIT(0);

#define DEVICE_NAME "rscaller"

static ssize_t rscaller_proc_read(struct file *, char __user *, size_t, loff_t *);
static void patch_ptr_params(int nr, const unsigned long *params, int slot_idx);

#ifdef HAVE_PROC_OPS
static const struct proc_ops rscaller_ops = {
	.proc_open    = rscaller_dev_open_new,
	.proc_read    = rscaller_proc_read,
	.proc_mmap    = rscaller_dev_mmap_new,
	.proc_release = rscaller_dev_release_new,
	.proc_write   = rscaller_proc_write,
};
#else
static const struct file_operations rscaller_ops = {
	.mmap    = rscaller_dev_mmap,
	.release = rscaller_dev_release,
	.write   = rscaller_proc_write,
};
#endif

static const void* rscaller_ops_ptr = (void*)&rscaller_ops;


#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
static inline void write_cr0_forced(unsigned long val)
{
	unsigned long __force_order;

	asm volatile(
		"mov %0, %%cr0"
		: "+r"(val), "+m"(__force_order));
}
#endif

static inline void smap_write_enable(void)
{
#if IS_ENABLED(CONFIG_X86) || IS_ENABLED(CONFIG_X86_64)
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
	write_cr0_forced(cr0);
#else
	write_cr0(cr0);
#endif
#elif IS_ENABLED(CONFIG_ARM64)
	update_mapping_prot(__pa_symbol(start_rodata), (unsigned long)start_rodata,
			section_size, PAGE_KERNEL_RO);

#endif
}

static inline void smap_write_disable(void)
{
#if IS_ENABLED(CONFIG_X86) || IS_ENABLED(CONFIG_X86_64)
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
	write_cr0_forced(cr0 & ~0x00010000);
#else
	write_cr0(cr0 & ~0x00010000);
#endif
#elif IS_ENABLED(CONFIG_ARM64)
	update_mapping_prot(__pa_symbol(start_rodata), (unsigned long)start_rodata,
			section_size, PAGE_KERNEL);
#endif
}

static inline void smap_rw_disable(void)
{
	stac();
}

static inline void smap_rw_enable(void)
{
	clac();
}


// TODO: separately handle userspace char buffers
int save_syscall_param(SyscallParam *buf, long param, int param_idx,
                       const SyscallSignature *signature, int slot_idx)
{
	void* inner_buf;
	bool is_ptr = signature->params_meta[param_idx].is_ptr;
	int type_variant = signature->params_meta[param_idx].type;
	size_t param_size = signature->params_meta[param_idx].size;
	int direction = signature->params_meta[param_idx].direction;

	fetch_param_variant(buf, type_variant, &inner_buf, &param_size);

	if (is_ptr) {
		ParamBuf *pb = &global_ctl_buffer->bufs[slot_idx].params[param_idx];

		/* Record the userspace pointer (used later for copy_to_user on OUT)
		 * and the direction so userspace knows what to do. */
		pb->user_ptr  = (uint64_t)param;
		pb->size      = (uint32_t)param_size;
		pb->direction = (uint32_t)direction;

		if (direction == PARAM_DIR_IN || direction == PARAM_DIR_INOUT) {
			if (copy_from_user(pb->data, (const void __user *)param, param_size)) {
				pr_err("Failed to copy IN param data from user space");
				return -EFAULT;
			}
		} else {
			/* OUT-only: nothing to copy in yet, just zero the buffer slot. */
			memset(pb->data, 0, param_size);
		}

		/* Also store the original userspace pointer value into the param
		 * union so the rest of the pipeline still sees an args[] entry. */
		memcpy(inner_buf, &param, sizeof(long) < param_size ? sizeof(long) : sizeof(unsigned long));
	} else {
		/* Bug F fix: param is a value, not a pointer — use &param */
		memcpy(inner_buf, &param, param_size);
	}

	return 0;
}

/* Bug A fix: add return syscall; before err: label; fix goto to free syscall */
Syscall* save_syscall(unsigned long *params, const SyscallSignature *signature, int slot_idx) {
	Syscall* syscall;
	int ret;
	int i;

	syscall = kvmalloc(sizeof(Syscall), GFP_KERNEL);
	if (syscall == NULL) {
		pr_err("Failed to alloc syscall buf");
		return NULL;
	}
	memset(syscall, 0, sizeof(Syscall));
	syscall->n_params = signature->n_params;

	for (i = 0; i < signature->n_params; i++) {
		RSC_LOG("rscaller: Trying to save param %d", i);
		ret = save_syscall_param(&(syscall->param_bufs[i]), params[i], i, signature, slot_idx);
		if (ret != 0) {
			pr_err("Failed to save syscall params");
			goto err;
		}
	}

	RSC_LOG("rscaller: Saved syscall params");
	return syscall;  /* success */

err:
	kvfree(syscall);
	return NULL;
}


/* Returns true (filter OUT / don't forward) if the current process should not
 * have its syscalls forwarded.  Two independent filter modes:
 *   - cgroup ns inode: all processes in a container share one unique inode
 *   - progs folder:    binary exe path starts with remote_progs_folder prefix
 * If neither is configured, nothing is forwarded. */
bool filter_binary(void) {
	/* --- cgroup namespace mode --- */
	if (container_cgns_inum != 0) {
		struct cgroup_namespace *cgns;
		if (!current->nsproxy)
			return true;
		cgns = current->nsproxy->cgroup_ns;
		if (!cgns)
			return true;
		return cgns->ns.inum != container_cgns_inum;
	}

	/* --- remote_progs_folder prefix mode --- */
	if (remote_progs_folder[0] != '\0') {
		struct file *exe;
		char *buf, *path;
		bool filter_out = true;
		size_t prefix_len = strlen(remote_progs_folder);

		if (!current->mm)
			return true;

		exe = current->mm->exe_file;
		if (!exe)
			return true;

		buf = kmalloc(PATH_MAX, GFP_KERNEL);
		if (!buf)
			return true;

		path = d_path(&exe->f_path, buf, PATH_MAX);
		if (!IS_ERR(path) && strncmp(path, remote_progs_folder, prefix_len) == 0)
			filter_out = false;

		kfree(buf);
		return filter_out;
	}

	/* nothing configured */
	return true;
}

inline int handle_syscall_common(const struct pt_regs *pt_regs,
                                  SyscallSignature *signature,
                                  int *ret) {
	Syscall *syscall;
	int slot_idx;
	int i;
	unsigned long params[6] = {
		pt_regs->di,
		pt_regs->si,
		pt_regs->dx,
		pt_regs->r10,
		pt_regs->r8,
		pt_regs->r9,
	};

	smap_rw_disable();

	if (!atomic_read(&rsclient_active)) {
		smap_rw_enable();
		return -1;
	}

	/* Let exit/exit_group terminate the local process normally — no forwarding */
	if (pt_regs->orig_ax == 60 || pt_regs->orig_ax == 231) {
		smap_rw_enable();
		return -1;
	}

	if (filter_binary()) {
		smap_rw_enable();
		return -1;
	}

	/* Reserve a slot first so save_syscall can populate that slot's bufs. */
	syscall = kvmalloc(sizeof(Syscall), GFP_KERNEL);
	if (!syscall) {
		smap_rw_enable();
		return -1;
	}
	memset(syscall, 0, sizeof(Syscall));
	syscall->number = (int)pt_regs->orig_ax;
	slot_idx = control_buffer_submit_syscall(global_ctl_buffer, syscall);
	kvfree(syscall);
	if (slot_idx < 0) {
		smap_rw_enable();
		return -1;
	}

	/* Now save the params (including IN buffers) into the reserved slot. */
	patch_ptr_params((int)pt_regs->orig_ax, params, slot_idx);
	syscall = save_syscall((unsigned long*)&params, signature, slot_idx);
	if (syscall) {
		/* Overwrite the placeholder we submitted earlier with the real syscall. */
		syscall->number = (int)pt_regs->orig_ax;
		memcpy(&global_ctl_buffer->kernel_to_user.nodes[slot_idx], syscall, sizeof(Syscall));
		kvfree(syscall);
	}

	*ret = (int)control_buffer_wait_result(global_ctl_buffer, slot_idx);

	/* Copy OUT/INOUT param buffers back to userspace.
	 * Check both signature IS_PTR entries AND runtime-patched ParamBufs
	 * (patch_ptr_params sets user_ptr for params not in the signature). */
	for (i = 0; i < MAX_PARAMS; i++) {
		ParamBuf *pb = &global_ctl_buffer->bufs[slot_idx].params[i];
		if ((pb->direction == PARAM_DIR_OUT || pb->direction == PARAM_DIR_INOUT) &&
		    pb->size > 0 && pb->user_ptr) {
			copy_to_user((void __user *)pb->user_ptr, pb->data, pb->size);
		}
	}

	smap_rw_enable();
	return 0;
}

/*
 * Populate ParamBuf entries for well-known syscalls that pass pointer args
 * whose size is determined at runtime (e.g. write's buffer size = arg2).
 * Called after the slot is reserved so bufs[slot_idx] is safe to write.
 */
static void patch_ptr_params(int nr, const unsigned long *params, int slot_idx)
{
	ParamBuf *pb;
	size_t sz;

	switch (nr) {
	case 1: /* write(fd, buf, count) — arg1=IN buf, size=arg2 */
		sz = min((unsigned long)params[2], (unsigned long)MAX_PARAM_BUF);
		pb = &global_ctl_buffer->bufs[slot_idx].params[1];
		pb->user_ptr  = params[1];
		pb->size      = (uint32_t)sz;
		pb->direction = PARAM_DIR_IN;
		if (sz && params[1])
			copy_from_user(pb->data, (const void __user *)params[1], sz);
		break;

	case 0: /* read(fd, buf, count) — arg1=OUT buf, size=arg2 */
		sz = min((unsigned long)params[2], (unsigned long)MAX_PARAM_BUF);
		pb = &global_ctl_buffer->bufs[slot_idx].params[1];
		pb->user_ptr  = params[1];
		pb->size      = (uint32_t)sz;
		pb->direction = PARAM_DIR_OUT;
		memset(pb->data, 0, sz);
		break;

	case 59: /* execve(filename, argv, envp) — arg0=IN filename (NUL-term) */
		pb = &global_ctl_buffer->bufs[slot_idx].params[0];
		pb->user_ptr  = params[0];
		pb->size      = (uint32_t)MAX_PARAM_BUF;
		pb->direction = PARAM_DIR_IN;
		if (params[0])
			strncpy_from_user(pb->data, (const char __user *)params[0], MAX_PARAM_BUF);
		break;

	case 2: /* open(pathname, flags, mode) — arg0=IN pathname */
	case 257: /* openat(dirfd, pathname, flags, mode) — arg1=IN pathname */ {
		int idx = (nr == 257) ? 1 : 0;
		pb = &global_ctl_buffer->bufs[slot_idx].params[idx];
		pb->user_ptr  = params[idx];
		pb->size      = (uint32_t)MAX_PARAM_BUF;
		pb->direction = PARAM_DIR_IN;
		if (params[idx])
			strncpy_from_user(pb->data, (const char __user *)params[idx], MAX_PARAM_BUF);
		break;
	}
	default:
		break;
	}
}

/* Generic signature: forward all 6 args as opaque longs, no pointer chasing */
static SyscallSignature generic_signature = {
	.n_params = 6,
	.params_meta = {
		{ LONG_TYPE, sizeof(long), NOT_PTR, PARAM_DIR_IN },
		{ LONG_TYPE, sizeof(long), NOT_PTR, PARAM_DIR_IN },
		{ LONG_TYPE, sizeof(long), NOT_PTR, PARAM_DIR_IN },
		{ LONG_TYPE, sizeof(long), NOT_PTR, PARAM_DIR_IN },
		{ LONG_TYPE, sizeof(long), NOT_PTR, PARAM_DIR_IN },
		{ LONG_TYPE, sizeof(long), NOT_PTR, PARAM_DIR_IN },
	},
};

KHOOK_EXT(long, x64_sys_call, const struct pt_regs *, unsigned int);
static long khook_x64_sys_call(const struct pt_regs *regs, unsigned int nr)
{
	int ret = 0;

	/* Process lifecycle: must execute locally so the container process tree
	 * stays intact and execve doesn't replace the beacon process.
	 * fork=57, vfork=58, clone=56, clone3=435, execve=59, execveat=322 */
	if (nr == 56 || nr == 57 || nr == 58 || nr == 59 ||
	    nr == 322 || nr == 435)
		return KHOOK_ORIGIN(x64_sys_call, regs, nr);

	/* stdio fd I/O: execute locally to preserve terminal interaction.
	 * Forwarding read(0) blocks forever since the beacon has no terminal
	 * input; forwarding write(1/2) silently drops output. */
	if ((nr == 0 || nr == 1) && regs->di < 3)
		return KHOOK_ORIGIN(x64_sys_call, regs, nr);
	/* close(3): don't close the beacon-side fd when the local fd is stdio */
	if (nr == 3 && regs->di < 3)
		return KHOOK_ORIGIN(x64_sys_call, regs, nr);

	if (handle_syscall_common(regs, &generic_signature, &ret) == 0)
		return ret;
	return KHOOK_ORIGIN(x64_sys_call, regs, nr);
}

int init_hooks(void) {
	return khook_init(NULL);
}

void cleanup_hooks(void) {
	khook_cleanup();
}


static int rscaller_dev_open_new(struct inode *inodep, struct file *filep) {
	int ret = 0;

	if (!mutex_trylock(&ctl_buffer_mutex)) {
		RSC_LOG("rscaller: device busy!\n");
		ret = -EBUSY;
		goto out;
	}

	RSC_LOG("rscaller: device opened\n");
	atomic_set(&rsclient_active, 1);

out:
	return ret;
}


static int rscaller_dev_mmap_old(struct inode *inodp, struct file *filp) {
	RSC_LOG("rscaller_dev_mmap_old");
	return 0;
}

static int rscaller_dev_mmap_new(struct file *filp, struct vm_area_struct *vma)
{
	unsigned long size = vma->vm_end - vma->vm_start;
	int ret;

	pr_info("rscaller: mmap size=%lu PAGE_ALIGN(CB)=%lu CB=%lu\n",
		size, PAGE_ALIGN(sizeof(ControlBuffer)), sizeof(ControlBuffer));

	/* mmap() rounds len up to PAGE_SIZE; allow that */
	if (size > PAGE_ALIGN(sizeof(ControlBuffer))) {
		pr_info("rscaller: mmap EINVAL size check\n");
		return -EINVAL;
	}

	vm_flags_set(vma, VM_IO | VM_DONTEXPAND | VM_DONTDUMP);

	/* remap_pfn_range works correctly for multi-page __get_free_pages
	 * allocations; vm_insert_page fails on tail pages (compound page
	 * tail pages have refcount 0). */
	ret = remap_pfn_range(vma, vma->vm_start,
	                      virt_to_phys(global_ctl_buffer) >> PAGE_SHIFT,
	                      size, vma->vm_page_prot);
	return ret;
}

/* Bug B fix: private_data is never set, remove free_page/kfree — only unlock */
static int rscaller_dev_release_new(struct inode *inode, struct file *filp)
{
	int i;
	RSC_LOG("rscaller: release\n");
	atomic_set(&rsclient_active, 0);
	/* Wake up any processes blocked in control_buffer_wait_result so they
	 * don't stay in D state forever after rsclient disconnects. */
	for (i = 0; i < BUFFER_SIZE; i++)
		control_buffer_complete(global_ctl_buffer, i, -ECONNRESET);
	mutex_unlock(&ctl_buffer_mutex);
	return 0;
}

/* Stub proc_read to allow O_RDWR opens (kernel rejects read flag without this) */
static ssize_t rscaller_proc_read(struct file *file, char __user *buf,
                                   size_t count, loff_t *ppos)
{
	return 0;
}

/* Format: "DONE <slot_idx> <retval>\n" */
ssize_t rscaller_proc_write(struct file *file, const char __user *buf,
                             size_t count, loff_t *ppos) {
	char kbuf[64];
	int slot_idx;
	long retval;

	if (count >= sizeof(kbuf))
		return -EINVAL;
	if (copy_from_user(kbuf, buf, count))
		return -EFAULT;
	kbuf[count] = '\0';

	if (sscanf(kbuf, "DONE %d %ld", &slot_idx, &retval) == 2) {
		if (slot_idx >= 0 && slot_idx < BUFFER_SIZE) {
			control_buffer_complete(global_ctl_buffer, slot_idx, retval);
		}
	}
	return count;
}

/* Bug D fix: ret initialized to 0 */
static int __init rscaller_init(void)
{
	int ret = 0;

	RSC_LOG("Rscaller init");

	global_ctl_buffer = control_buffer_new();

	if ((ret = init_hooks())) {
		pr_err("Failed to register hooks");
		return ret;
	}

	proc_create(DEVICE_NAME, 0666, NULL, rscaller_ops_ptr);

	return 0;
}

static void __exit rscaller_cleanup(void)
{
	cleanup_hooks();
	remove_proc_entry(DEVICE_NAME, NULL);
	control_buffer_free(global_ctl_buffer);
}

static void vm_close(struct vm_area_struct *vma)
{
	RSC_LOG("vm_close\n");
}


module_init(rscaller_init);
module_exit(rscaller_cleanup);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("your mom");
MODULE_DESCRIPTION("Rscaller kmod");
