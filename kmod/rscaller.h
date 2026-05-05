#ifndef RSCALLER
#define RSCALLER

#include "buffer.h"


#define MODULE_NAME "rscaller"

/* TODO: include syscall entries in codegen */

struct mmap_info {
    char *data;
};

void fetch_param_variant(SyscallParam *src, int param_type, void **param, size_t *param_size);

static int rscaller_dev_mmap_new(struct file *filp, struct vm_area_struct *vma);
static int rscaller_dev_mmap_old(struct inode *inode, struct file *filp);

static int rscaller_dev_release_new(struct inode *inode, struct file *filp);

static int rscaller_dev_open_new(struct inode *inodep, struct file *filep);

ssize_t rscaller_proc_write(struct file *file, const char __user *buf,
                             size_t count, loff_t *ppos);

#endif
