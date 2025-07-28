#ifndef RSCALLER_CONTROL_BUFFER
#define RSCALLER_CONTROL_BUFFER

#include "types.h"

#ifdef __USERSPACE__
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#endif

#ifdef __USERSPACE__
#define RSC_LOG printf
#define RSC_MALLOC(n) malloc(n)
#define RSC_FREE(n) free(n)
#else
#define RSC_LOG pr_debug
#define RSC_MALLOC(n) kmalloc(n, GFP_KERNEL)
#define RSC_FREE(n) kfree(n)
#endif


#define BUFFER_SIZE 1024


typedef struct MemoryQueue{
    Syscall* head;
    int size; // defaulted to BUFFER_SIZE
    Syscall nodes[BUFFER_SIZE];
} MemoryQueue;

typedef struct ControlBuffer {
    MemoryQueue kernel_to_user;
    MemoryQueue user_to_kernel;
} ControlBuffer;

static ControlBuffer global_control_buffer;

// ControlBuffer* control_buffer_new(void);
void control_buffer_init(ControlBuffer *cb);
void control_buffer_free(ControlBuffer *cb);

int control_buffer_submit_syscall(ControlBuffer *cb, Syscall *syscall);


// Initialize ring buffer
MemoryQueue* mem_queue_new(void);
void mem_queue_free(MemoryQueue *buf);

// Push syscall to the user-space
int mem_queue_push(MemoryQueue *buf, Syscall *syscall);
// Consume the syscall if applicable
Syscall* mem_queue_pop(MemoryQueue *buf);
// Print size of the ring buffer
int mem_queue_size(void);

#endif