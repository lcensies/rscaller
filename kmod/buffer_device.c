#include "rscaller.h"

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