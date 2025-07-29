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

// #if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
// #define KPROBE_LOOKUP 1
// #include <linux/kprobes.h>
// static struct kprobe kp_kallsyms = {
//     .symbol_name = "kallsyms_lookup_name",
// };
// #endif


#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)
#define HAVE_PROC_OPS
#endif

// static unsigned long *__sys_call_table;
// typedef asmlinkage long (*t_syscall)(const struct pt_regs *);
// static t_syscall orig_syscall;

#define REMOTE_PROGS_FOLDER "/remote_progs/"
#define DEVICE_NAME "rscaller"

#ifdef HAVE_PROC_OPS
static const struct proc_ops rscaller_ops = {
	.proc_open = rscaller_dev_open_new,
    .proc_mmap = rscaller_dev_mmap_new,
    .proc_release = rscaller_dev_release_new,
};
#else
static const struct file_operations rscaller_ops = {
    .mmap = rscaller_dev_mmap,
    .release = rscaller_dev_release,
};
#endif

static const void* rscaller_ops_ptr = (void*)&rscaller_ops;

// unsigned long * get_syscall_table(void)
// {
// 	#ifdef KPROBE_LOOKUP
// 		unsigned long (*kallsyms_lookup_name)(const char *name);
// 		if (register_kprobe(&kp_kallsyms) < 0)
// 			return 0;
// 		kallsyms_lookup_name = (unsigned long (*)(const char *name)) kp_kallsyms.addr;
// 		unregister_kprobe(&kp_kallsyms);
// 	#endif

// 	unsigned long * syscall_table;

// 	syscall_table = (unsigned long*)kallsyms_lookup_name("sys_call_table");
// 	return syscall_table;
// }


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

	// TODO: use macro to auto fetch specific variant
	fetch_param_variant(buf, type_variant, &inner_buf, &param_size);

	// Here we handle all pointers except char buffers
	// param_size is taken from real size of struct
	if (is_ptr) {
		// RSC_LOG("Trying to allocate %d bytes\n", param_size);
        src_kernel = kvmalloc(param_size, GFP_KERNEL);
        if (!src_kernel) {
            pr_err("Failed to allocate temp buf for syscall");
            return -ENOMEM; // it's good practice to return a proper error code
        }

        // Copy the data from user space to the kernel buffer
        if (copy_from_user(src_kernel, (const void __user *)inner_buf, param_size)) {
            kvfree(src_kernel); // Free the allocated buffer in case of failure
            pr_err("Failed to copy data from user space");
            return -EFAULT; // Return an error if copy fails
        }

        // Now use src_kernel as the source for memcpy
        memcpy(inner_buf, src_kernel, param_size);
        kvfree(src_kernel); // Free the allocated buffer after copying
    } 
	else {
        memcpy(inner_buf, (void *)param, param_size); // Unsafe, we should ensure 'param' is valid!
	}


	return 0;
}

Syscall* save_syscall(unsigned long *params, const SyscallSignature *signature) {
	Syscall* syscall;
	int ret;
	int i;

	syscall = kvmalloc(sizeof(Syscall), GFP_KERNEL);
	if (syscall == NULL) {
		pr_err("Failed to alloc syscall buf");
		return NULL;
	}

	smap_rw_disable();
	for(i = 0; i < signature->n_params; i++) {

		RSC_LOG("rscaller: Trying to save param %d", i);
		ret = save_syscall_param(&(syscall->param_bufs[i]), params[i], i, signature);
		if (ret == -1) {
			pr_err("Failed to save syscall params");
			return NULL;
		}
	}
	smap_rw_enable();

	RSC_LOG("rscaller: Saved syscall params");

err:
	kfree(syscall);
	return NULL;
}


// // Might be needed in case if it will be more convenient to save additional meta
// // inside ParamBuf
// // param_prepare_meta(ParamBuffer *buf, const SyscallSignature *signature, int param_idx) {
// // }


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
	char  *binary = get_current_binary_path();

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
	smap_rw_disable();
	Syscall *syscall;	
	unsigned long params[6] = {
		pt_regs->bx,
		pt_regs->cx,
		pt_regs->dx,
		pt_regs->si,
		pt_regs->di,
		pt_regs->bp,
	};
    
    RSC_LOG("handle_syscall_common");

	// Binary is outside of remote_progs folder
	if (!filter_binary()) {
        return -1;
		// return orig_syscall(pt_regs);
	}


	// // smap_write_disable();
	syscall = save_syscall((unsigned long*)&params, signature);
	// // smap_write_enable();

	*ret = control_buffer_submit_syscall(&global_ctl_buffer, syscall);

	smap_rw_enable();
	return 0;
}

asmlinkage int hooked_syscall___x64_sys_kill(const struct pt_regs *pt_regs);

// Wrapper for calling original syscall based on it's name
// across different hooking engines
#define ORIGINAL_SYSCALL(name, regs) KHOOK_ORIGIN(__x64_sys_kill, regs)

#define DEFINE_HOOKED_SYSCALL(name) \
asmlinkage int hooked_syscall_##name(const struct pt_regs *pt_regs) \
{ \
    int ret; \
    bool sent_remote; \
    SyscallSignature signature; \
    sent_remote = handle_syscall_common(pt_regs, &signature##name, &ret); \
    ret = ORIGINAL_SYSCALL(name, pt_regs); \
    return ret; \
}

// if (!sent_remote) { \
//     return ORIGINAL_SYSCALL(name, pt_regs); \
// } \


KHOOK_EXT(long, __x64_sys_kill, const struct pt_regs *);
static long khook___x64_sys_kill(const struct pt_regs *regs) {
        printk("sys_kill -- %s pid %ld sig %ld\n", current->comm, regs->di, regs->si);
		return hooked_syscall___x64_sys_kill(regs);
        // return ORIGINAL_SYSCALL(__x64_sys_kill, regs);
}

DEFINE_HOOKED_SYSCALL(__x64_sys_kill)

int init_hooks(void) {
	// __sys_call_table = get_syscall_table();
	// if (!__sys_call_table)
	// 	return -1;
    return khook_init(NULL);
}



void cleanup_hooks(void) {
	// smap_write_disable();
	// __sys_call_table[syscall_num] = (unsigned long) orig_syscall;
	// smap_write_enable();

	khook_cleanup();
}

static int rscaller_dev_open_new(struct inode *inodep, struct file *filep) {
    int ret = 0; 

    if(!mutex_trylock(&ctl_buffer_mutex)) {
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
    return 0;
}

static int rscaller_dev_release_new(struct inode *inode, struct file *filp)
{
    struct mmap_info *info;

    RSC_LOG("rscaller: release\n");

    info = filp->private_data;
    free_page((unsigned long)info->data);
    kfree(info);
    filp->private_data = NULL;

	mutex_unlock(&ctl_buffer_mutex);

    return 0;
}


static int __init rscaller_init(void)
{
	int ret;

	RSC_LOG("Rscaller init");

	// if (ret = init_hooks()) {
	// 	pr_err("Failed to register hooks");
	// 	return ret;
	// }
	
	control_buffer_init(&global_ctl_buffer);
    proc_create(DEVICE_NAME, 0, NULL, rscaller_ops_ptr);

    return 0;
}

static void __exit rscaller_cleanup(void)
{
	cleanup_hooks();

	remove_proc_entry(DEVICE_NAME, NULL);
}

/* After unmap. */
static void vm_close(struct vm_area_struct *vma)
{
    RSC_LOG("vm_close\n");
}

/* First page access. */
// static vm_fault_t vm_fault(struct vm_fault *vmf)
// {
//     struct page *page;
//     struct mmap_info *info;

//     RSC_LOG("vm_fault\n");
//     info = (struct mmap_info *)vmf->vma->vm_private_data;
//     if (info->data) {
//         page = virt_to_page(info->data);
//         get_page(page);
//         vmf->page = page;
//     }
//     return 0;
// }

/* After mmap. TODO vs mmap, when can this happen at a different time than mmap? */
// static void rscaller_dev_open_new(struct vm_area_struct *vma)
// {
//     RSC_LOG("vm_open\n");
// }

// static struct vm_operations_struct vm_ops =
// {
//     .close = vm_close,
//     .fault = vm_fault,
//     .open = vm_open,
// };

// https://github.com/cirosantilli/linux-kernel-module-cheat/blob/2ea5e17d23553334c23934d83965de8a47df3780/kernel_modules/mmap.c



module_init(rscaller_init);
module_exit(rscaller_cleanup);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("your mom");
MODULE_DESCRIPTION("Rscaller kmod");
