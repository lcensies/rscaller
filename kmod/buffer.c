#include "buffer.h"

/* Bug C fix: define globals once here */
ControlBuffer *global_ctl_buffer;
#ifndef __USERSPACE__
DEFINE_MUTEX(ctl_buffer_mutex);
#endif

/* TODO: parametrize */
#define BUFFER_PATH "/tmp/rscaller_buf"

void mem_queue_init(MemoryQueue *queue) {
    int i;
    memset(queue, 0, sizeof(MemoryQueue));
    queue->max_size = BUFFER_SIZE;
#ifndef __USERSPACE__
    mutex_init(&queue->lock);
    for (i = 0; i < BUFFER_SIZE; i++) {
        init_completion(&queue->slot_completions[i]);
        queue->slot_retvals[i] = 0;
    }
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
    mutex_lock(&queue->lock);
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
    mutex_unlock(&queue->lock);
#endif
    return ret;
}

Syscall* mem_queue_pop(MemoryQueue *queue)
{
    Syscall *ret;

#ifndef __USERSPACE__
    mutex_lock(&queue->lock);
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
    mutex_unlock(&queue->lock);
#endif
    return ret;
}


void control_buffer_init(ControlBuffer *cb) {
    RSC_LOG("rscaller: control_buffer_init");
    mem_queue_init(&cb->kernel_to_user);
    mem_queue_init(&cb->user_to_kernel);
}

ControlBuffer* control_buffer_new(void) {
    ControlBuffer *buf;

    RSC_LOG("rscaller: control_buffer_new");

    buf = RSC_MALLOC(sizeof(ControlBuffer));
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
    mutex_lock(&queue->lock);
#endif
    if (queue->size == queue->max_size) {
        RSC_LOG("rscaller: Memory queue is full");
#ifndef __USERSPACE__
        mutex_unlock(&queue->lock);
#endif
        return -1;
    }

    queue->tail_idx = (queue->tail_idx + queue->max_size - 1) % queue->max_size;
    mem_queue_node_init(&(queue->nodes[queue->tail_idx]), syscall);
    queue->size += 1;
    slot_idx = queue->tail_idx;
#ifndef __USERSPACE__
    mutex_unlock(&queue->lock);
#endif

    return slot_idx;
}

#ifndef __USERSPACE__
long control_buffer_wait_result(ControlBuffer *cb, int slot_idx) {
    wait_for_completion_interruptible(&cb->kernel_to_user.slot_completions[slot_idx]);
    return cb->kernel_to_user.slot_retvals[slot_idx];
}

void control_buffer_complete(ControlBuffer *cb, int slot_idx, long retval) {
    cb->kernel_to_user.slot_retvals[slot_idx] = retval;
    complete(&cb->kernel_to_user.slot_completions[slot_idx]);
}
#endif

#ifndef __GENERATING_BINDINGS__
MODULE_LICENSE("GPL");
MODULE_AUTHOR("your mom");
MODULE_DESCRIPTION("Rscaller kmod");
#endif
