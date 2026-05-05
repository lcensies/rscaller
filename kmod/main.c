#include "rscaller.h"

#include <linux/syscalls.h>
#include <linux/dirent.h>
#include <linux/slab.h>
#include <linux/version.h> 

#include <linux/module.h>
#include <linux/sched.h>
#include <linux/mm.h>

#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h> /* min */
#include <linux/proc_fs.h>
#include <linux/uaccess.h> /* copy_from_user, copy_to_user */
#include <linux/slab.h>

#include <khook/engine.h>


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

#define REMOTE_PROGS_FOLDER "/remote_progs/"
#define DEVICE_NAME "rscaller"

#ifdef HAVE_PROC_OPS
static const struct proc_ops rscaller_ops = {
	.proc_open    = rscaller_dev_open_new,
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
int save_syscall_param(SyscallParam *buf, long param, int param_idx, const SyscallSignature *signature)
{
	void* inner_buf;
	void* src_kernel;
	bool is_ptr = signature->params_meta[param_idx].is_ptr;
	int type_variant = signature->params_meta[param_idx].type;
	size_t param_size = signature->params_meta[param_idx].size;

	fetch_param_variant(buf, type_variant, &inner_buf, &param_size);

	if (is_ptr) {
		src_kernel = kvmalloc(param_size, GFP_KERNEL);
		if (!src_kernel) {
			pr_err("Failed to allocate temp buf for syscall");
			return -ENOMEM;
		}

		if (copy_from_user(src_kernel, (const void __user *)inner_buf, param_size)) {
			kvfree(src_kernel);
			pr_err("Failed to copy data from user space");
			return -EFAULT;
		}

		memcpy(inner_buf, src_kernel, param_size);
		kvfree(src_kernel);
	} else {
		/* Bug F fix: param is a value, not a pointer — use &param */
		memcpy(inner_buf, &param, param_size);
	}

	return 0;
}

/* Bug A fix: add return syscall; before err: label; fix goto to free syscall */
Syscall* save_syscall(unsigned long *params, const SyscallSignature *signature) {
	Syscall* syscall;
	int ret;
	int i;

	syscall = kvmalloc(sizeof(Syscall), GFP_KERNEL);
	if (syscall == NULL) {
		pr_err("Failed to alloc syscall buf");
		return NULL;
	}

	for (i = 0; i < signature->n_params; i++) {
		RSC_LOG("rscaller: Trying to save param %d", i);
		ret = save_syscall_param(&(syscall->param_bufs[i]), params[i], i, signature);
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


char *get_current_binary_path(void)
{
	struct mm_struct *mm;
	char *buf, *res;

	mm = current->mm;
	if (!mm || !mm->exe_file)
		return NULL;

	buf = kvmalloc(PATH_MAX, GFP_KERNEL);
	if (!buf)
		return NULL;

	res = d_path(&mm->exe_file->f_path, buf, PATH_MAX);
	if (IS_ERR(res)) {
		pr_err("d_path failed: %ld\n", PTR_ERR(res));
		kvfree(buf);
		return NULL;
	}

	res = kstrdup(res, GFP_KERNEL);
	kvfree(buf);
	return res;
}


bool filter_binary(void) {
	bool is_filtered;
	char *binary = get_current_binary_path();

	if (binary == NULL) {
		return false;
	}

	is_filtered = !strstr(binary, REMOTE_PROGS_FOLDER);

	if (!is_filtered) {
		RSC_LOG("%s performed syscall\n", binary);
	}

	kvfree(binary);
	return is_filtered;
}

inline int handle_syscall_common(const struct pt_regs *pt_regs,
                                  SyscallSignature *signature,
                                  int *ret) {
	Syscall *syscall;
	int slot_idx;
	unsigned long params[6] = {
		pt_regs->bx,
		pt_regs->cx,
		pt_regs->dx,
		pt_regs->si,
		pt_regs->di,
		pt_regs->bp,
	};

	smap_rw_disable();

	RSC_LOG("handle_syscall_common");

	if (!filter_binary()) {
		smap_rw_enable();
		return -1;
	}

	syscall = save_syscall((unsigned long*)&params, signature);

	slot_idx = control_buffer_submit_syscall(global_ctl_buffer, syscall);
	if (slot_idx >= 0) {
		*ret = (int)control_buffer_wait_result(global_ctl_buffer, slot_idx);
	}

	smap_rw_enable();
	return 0;
}

asmlinkage int hooked_syscall___x64_sys_kill(const struct pt_regs *pt_regs);

/* Wrapper for calling original syscall based on its name across different hooking engines */
#define ORIGINAL_SYSCALL(name, regs) KHOOK_ORIGIN(__x64_sys_kill, regs)

/* Bug E fix: sent_remote is int (not bool); macro compiles and runs original always for now */
#define DEFINE_HOOKED_SYSCALL(name) \
asmlinkage int hooked_syscall_##name(const struct pt_regs *pt_regs) \
{ \
	int ret = 0; \
	int sent_remote; \
	sent_remote = handle_syscall_common(pt_regs, &signature##name, &ret); \
	ret = ORIGINAL_SYSCALL(name, pt_regs); \
	return ret; \
}


KHOOK_EXT(long, __x64_sys_kill, const struct pt_regs *);
static long khook___x64_sys_kill(const struct pt_regs *regs) {
	printk("sys_kill -- %s pid %ld sig %ld\n", current->comm, regs->di, regs->si);
	return hooked_syscall___x64_sys_kill(regs);
}

DEFINE_HOOKED_SYSCALL(__x64_sys_kill)

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

out:
	return ret;
}


static int rscaller_dev_mmap_old(struct inode *inodp, struct file *filp) {
	RSC_LOG("rscaller_dev_mmap_old");
	return 0;
}

static int rscaller_dev_mmap_new(struct file *filp, struct vm_area_struct *vma)
{
	int ret = 0;
	struct page *page = NULL;
	unsigned long size = (unsigned long)(vma->vm_end - vma->vm_start);

	if (size > sizeof(ControlBuffer)) {
		ret = -EINVAL;
		goto out;
	}

	page = virt_to_page((unsigned long)&global_ctl_buffer + (vma->vm_pgoff << PAGE_SHIFT));
	ret = remap_pfn_range(vma, vma->vm_start, page_to_pfn(page), size, vma->vm_page_prot);
	if (ret != 0) {
		goto out;
	}

out:
	return ret;
}

/* Bug B fix: private_data is never set, remove free_page/kfree — only unlock */
static int rscaller_dev_release_new(struct inode *inode, struct file *filp)
{
	RSC_LOG("rscaller: release\n");
	mutex_unlock(&ctl_buffer_mutex);
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

	proc_create(DEVICE_NAME, 0, NULL, rscaller_ops_ptr);

	return 0;
}

static void __exit rscaller_cleanup(void)
{
	cleanup_hooks();
	remove_proc_entry(DEVICE_NAME, NULL);
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
