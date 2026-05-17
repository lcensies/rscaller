typedef unsigned long	__kernel_size_t;
typedef __kernel_size_t size_t;
typedef unsigned short umode_t;

#ifdef __GENERATING_BINDINGS__
   // Ignore asmlinkage while generating bindings
    #define asmlinkage
    // #include "vmlinux.h"
    #include <linux/types.h>
    #include "vmlinux_stripped.h"
#else
    // #include <linux/sched.h>
    #include <linux/module.h>
    #include <linux/syscalls.h>
    #include <linux/dirent.h>
    #include <linux/slab.h>
    #include <linux/version.h> 

    #include <linux/types.h>
    #include <linux/compat.h>
    // #include <asm/types.h>
    #include <asm/atomic.h>
    #include <asm/posix_types.h>
#endif

#ifdef __USERSPACE__
#define RSC_LOG printf
#define RSC_MALLOC(n) malloc(n)
#define RSC_FREE(n) free(n)
#else
#define RSC_LOG pr_info
#define RSC_MALLOC(n) kmalloc(n, GFP_KERNEL)
#define RSC_FREE(n) kfree(n)
#endif

#ifndef RSCALLER_TYPES

#define RSCALLER_TYPES
#define PTR true
#define NOT_PTR false

#define PARAM_DIR_IN    0
#define PARAM_DIR_OUT   1
#define PARAM_DIR_INOUT 2

// Compile time
typedef struct {
  int type;
  size_t size;
  int is_ptr;
  int direction;   /* PARAM_DIR_* */
} ParamMeta;

typedef struct {
  int n_params;
  ParamMeta params_meta[6]; 
} SyscallSignature;


#include "handler_wrappers.h"

typedef asmlinkage int (*syscall_ptr_t)(const struct pt_regs *pt_regs);

typedef struct {
  int number;
  int n_params;
  int ret;
  SyscallParam param_bufs[6];
} Syscall;

typedef struct {
  int number;
  char name[64];
  // int is_remote;
  SyscallSignature signature;
  
  syscall_ptr_t original_addr;
  syscall_ptr_t hooked_addr;
} SyscallEntry;

#endif