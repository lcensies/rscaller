#include "buffer.h"

// TODO: parametrize
#define BUFFER_PATH "/tmp/rscaller_buf"


void control_buffer_init(ControlBuffer *cb) {
    cb->kernel_to_user.size = 0;
    cb->user_to_kernel.size = 0;
}

int control_buffer_submit_syscall(ControlBuffer *cb, Syscall *syscall) {
    pr_info("Submitting syscall to control buffer");
    mem_queue_push(&cb->kernel_to_user, syscall)
    return 0;
}


MemoryQueue* mem_queue_new(void)
{
    MemoryQueue *queue = kmalloc(sizeof(*queue), GFP_KERNEL);
    if (!queue)
        return NULL;

    queue->head = queue->nodes;
    queue->size = 0;

    return queue;
}

void mem_queue_free(MemoryQueue *queue)
{
    kfree(queue);
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

    ret = kmalloc(sizeof(Syscall), GFP_KERNEL);
    memcpy(ret, src, sizeof(Syscall));

    return ret;
}

int mem_queue_push(MemoryQueue *queue, Syscall *syscall)
{
    Syscall *node;

    if (queue->size == BUFFER_SIZE) {
        pr_debug("Memory queue is full");
        return -1;
    }


    queue->size += 1;
    node = queue->head + sizeof(Syscall);
    queue->head = node;

    mem_queue_node_init(node, syscall);

    return 0;
}

Syscall* mem_queue_pop(MemoryQueue *queue)
{
    Syscall *node, *ret;
    
    if (queue->size == 0) {
        return NULL;
    }

    node = queue->head;
    queue->size -= 1;
    queue->head -= sizeof(Syscall);

    ret = mem_queue_node_copy(node);
    mem_queue_node_free(node);

    return ret;
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("your mom");
MODULE_DESCRIPTION("Rscaller kmod");
