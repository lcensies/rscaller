#include "buffer.h"

/* Bug C fix: define globals once here */
ControlBuffer *global_ctl_buffer;
#ifndef __USERSPACE__
DEFINE_MUTEX(ctl_buffer_mutex);

/* Kernel-only synchronisation state — NOT in the mmap'd ControlBuffer so that
 * the Rust ControlBuffer mirror stays layout-compatible with the kernel view. */
static struct mutex          ktu_lock;
static struct completion     ktu_completions[BUFFER_SIZE];
static long                  ktu_retvals[BUFFER_SIZE];
#endif

/* TODO: parametrize */
#define BUFFER_PATH "/tmp/rscaller_buf"

void mem_queue_init(MemoryQueue *queue) {
    int i;
    memset(queue, 0, sizeof(MemoryQueue));
    queue->max_size = BUFFER_SIZE;
#ifndef __USERSPACE__
    (void)i;
#else
    (void)i;
#endif
}

MemoryQueue* mem_queue_new(void)
{
    MemoryQueue *queue = RSC_MALLOC(sizeof(*queue));
    if (!queue)
        return NULL;

    mem_queue_init(queue);
    return queue;
}

void mem_queue_free(MemoryQueue *queue)
{
    RSC_FREE(queue);
}

inline void mem_queue_node_init(Syscall *node, Syscall *syscall) {
    memcpy(node, syscall, sizeof(Syscall));
}

inline void mem_queue_node_free(Syscall *node) {
    memset(node, 0, sizeof(Syscall));
}

/* Copies node from the in-memory buffer */
Syscall* mem_queue_node_copy(Syscall *src) {
    Syscall *ret;

    if (!src) {
        RSC_LOG("rscaller: mem_queue_node_copy: src is NULL");
        return NULL;
    }

    ret = RSC_MALLOC(sizeof(Syscall));
    if (!ret) {
        RSC_LOG("rscaller: mem_queue_node_copy: allocation failed");
        return NULL;
    }
    memcpy(ret, src, sizeof(Syscall));

    return ret;
}

int mem_queue_push(MemoryQueue *queue, Syscall *syscall)
{
    int ret = 0;
#ifndef __USERSPACE__
    mutex_lock(&ktu_lock);
#endif
    if (queue->size == queue->max_size) {
        RSC_LOG("rscaller: Memory queue is full");
        ret = -1;
        goto out;
    }

    queue->tail_idx = (queue->tail_idx + queue->max_size - 1) % queue->max_size;
    mem_queue_node_init(&(queue->nodes[queue->tail_idx]), syscall);
    queue->size += 1;

out:
#ifndef __USERSPACE__
    mutex_unlock(&ktu_lock);
#endif
    return ret;
}

Syscall* mem_queue_pop(MemoryQueue *queue)
{
    Syscall *ret;

#ifndef __USERSPACE__
    mutex_lock(&ktu_lock);
#endif
    if (queue->size == 0) {
        RSC_LOG("rscaller: Memory queue is empty");
        ret = NULL;
        goto out;
    }

    queue->head_idx = (queue->head_idx + queue->max_size - 1) % queue->max_size;
    queue->size -= 1;
    ret = mem_queue_node_copy(&(queue->nodes[queue->head_idx]));

out:
#ifndef __USERSPACE__
    mutex_unlock(&ktu_lock);
#endif
    return ret;
}


void control_buffer_free(ControlBuffer *cb) {
#ifndef __USERSPACE__
    free_pages((unsigned long)cb, get_order(sizeof(ControlBuffer)));
#else
    RSC_FREE(cb);
#endif
}

void control_buffer_init(ControlBuffer *cb) {
    int i;
    RSC_LOG("rscaller: control_buffer_init");
    mem_queue_init(&cb->kernel_to_user);
    mem_queue_init(&cb->user_to_kernel);
    memset(cb->bufs, 0, sizeof(cb->bufs));
#ifndef __USERSPACE__
    mutex_init(&ktu_lock);
    for (i = 0; i < BUFFER_SIZE; i++) {
        init_completion(&ktu_completions[i]);
        ktu_retvals[i] = 0;
    }
#else
    (void)i;
#endif
}

ControlBuffer* control_buffer_new(void) {
    ControlBuffer *buf;

    RSC_LOG("rscaller: control_buffer_new");

#ifndef __USERSPACE__
    /* Must use page allocator (not slab/kmalloc) so virt_to_page() returns
     * a properly refcounted page that vm_insert_page() will accept. */
    buf = (ControlBuffer *)__get_free_pages(GFP_KERNEL | __GFP_ZERO,
                                             get_order(sizeof(ControlBuffer)));
#else
    buf = RSC_MALLOC(sizeof(ControlBuffer));
#endif
    if (!buf)
        return NULL;
    control_buffer_init(buf);

    return buf;
}

/*
 * Returns the slot index used (>=0) on success, -1 on error.
 * Caller can use slot_idx with control_buffer_wait_result() to block
 * until userspace signals completion.
 */
int control_buffer_submit_syscall(ControlBuffer *cb, Syscall *syscall) {
    int slot_idx;
    MemoryQueue *queue = &cb->kernel_to_user;

    RSC_LOG("Submitting syscall to control buffer");

#ifndef __USERSPACE__
    mutex_lock(&ktu_lock);
#endif
    if (queue->size == queue->max_size) {
        RSC_LOG("rscaller: Memory queue is full");
#ifndef __USERSPACE__
        mutex_unlock(&ktu_lock);
#endif
        return -1;
    }

    /* Write at current tail, then advance forward — consistent with pop reading
     * from head and advancing forward.  Previous code went backward (tail-1)
     * while pop went forward, so slot_idx never matched head_idx. */
    slot_idx = queue->tail_idx;
    mem_queue_node_init(&(queue->nodes[slot_idx]), syscall);
    queue->tail_idx = (queue->tail_idx + 1) % queue->max_size;
    queue->size += 1;
#ifndef __USERSPACE__
    mutex_unlock(&ktu_lock);
#endif

    return slot_idx;
}

#ifndef __USERSPACE__
long control_buffer_wait_result(ControlBuffer *cb, int slot_idx) {
    (void)cb;
    wait_for_completion_interruptible(&ktu_completions[slot_idx]);
    return ktu_retvals[slot_idx];
}

void control_buffer_complete(ControlBuffer *cb, int slot_idx, long retval) {
    (void)cb;
    ktu_retvals[slot_idx] = retval;
    complete(&ktu_completions[slot_idx]);
}
#endif

#ifndef __GENERATING_BINDINGS__
MODULE_LICENSE("GPL");
MODULE_AUTHOR("your mom");
MODULE_DESCRIPTION("Rscaller kmod");
#endif

