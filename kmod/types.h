
// #include <linux/sched.h>
// #include <linux/module.h>
// #include <linux/syscalls.h>
// #include <linux/dirent.h>
// #include <linux/slab.h>
// #include <linux/version.h> 

// #include <sys/types.h>
// #include <linux/types.h>
// #include <linux/compat.h>
// #include <asm/types.h>
// #include <asm/atomic.h>
// #include <asm/posix_types.h>

#include "vmlinux.h"
// #include "handler_wrappers.h"




// Ignore asmlinkage while generating bindings
#ifdef __GENERATING_BINDINGS__
    #define asmlinkage
#endif

#define PTR true
#define NOT_PTR false

typedef asmlinkage int (*syscall_ptr_t)(const struct pt_regs *pt_regs);



typedef struct {
  int type;
  size_t size;
  int is_ptr;
} ParamMeta;

typedef struct {
  int n_params;
  ParamMeta params_meta[6]; 
} SyscallSignature;



typedef struct {
  int number;
  char name[64];
  // Since all existing syscalls have only one parameter for user buffer, it is safe to define the number of argument responsible for buffer. For more complex scenarios, we can store the entire function signature.
  // int buf_arg_idx;
  // Optional parameter specifying number of bytes for operation
  // The real buffer size should be greater or equal to it.
  // int buf_size_arg_idx; 
  SyscallSignature signature;
  
  syscall_ptr_t original_addr;
  syscall_ptr_t hooked_addr;
} SyscallEntry;

