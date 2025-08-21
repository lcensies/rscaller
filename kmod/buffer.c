#include "buffer.h"

// TODO: parametrize
#define BUFFER_PATH "/tmp/rscaller_buf"

void mem_queue_init(MemoryQueue *queue) {
    memset(queue, 0, sizeof(MemoryQueue));
    queue->max_size = BUFFER_SIZE;
    mutex_init(&queue->lock);
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


// Copies node from the in-memory buffer 
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
    mutex_lock(&queue->lock);
    if (queue->size == queue->max_size) {
        RSC_LOG("rscaller: Memory queue is full");
        ret = -1;
        goto out;
    }

    queue->tail_idx = (queue->tail_idx + queue->max_size - 1) % queue->max_size;
    mem_queue_node_init(&(queue->nodes[queue->tail_idx]), syscall);
    queue->size += 1;

out:
    mutex_unlock(&queue->lock);
    return ret;
}

Syscall* mem_queue_pop(MemoryQueue *queue)
{
    Syscall *node, *ret;
    
    mutex_lock(&queue->lock);
    if (queue->size == 0) {
        RSC_LOG("rscaller: Memory queue is empty");
        ret = NULL;
        goto out;
    }

    queue->head_idx = (queue->head_idx + queue->max_size - 1) % queue->max_size;
    queue->size -= 1;
    ret = mem_queue_node_copy(&(queue->nodes[queue->head_idx]));

out:
    mutex_unlock(&queue->lock);
    return ret;
}


void control_buffer_init(ControlBuffer *cb) {
    RSC_LOG("rscaller: control_buffer_init");
    mem_queue_init(&cb->kernel_to_user);
    mem_queue_init(&cb->user_to_kernel);
}

ControlBuffer* control_buffer_new() {
    ControlBuffer *buf;

    RSC_LOG("rscaller: control_buffer_new");

    buf = RSC_MALLOC(sizeof(ControlBuffer));
    control_buffer_init(buf);

    return buf;
}

int control_buffer_submit_syscall(ControlBuffer *cb, Syscall *syscall) {
    int ret;
    RSC_LOG("Submitting syscall to control buffer");
    ret = mem_queue_push(&(cb->kernel_to_user), syscall);
    return ret;
}

#ifndef __GENERATING_BINDINGS__
MODULE_LICENSE("GPL");
MODULE_AUTHOR("your mom");
MODULE_DESCRIPTION("Rscaller kmod");
#endif