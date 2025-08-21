#ifndef RSCALLER_CONTROL_BUFFER
#define RSCALLER_CONTROL_BUFFER

#include "types.h"

#ifdef __USERSPACE__
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#endif

#ifndef __USERSPACE__
#include <linux/mutex.h>
#endif


#define BUFFER_SIZE 10


typedef struct MemoryQueue{
    int size;
    int max_size;  // defaulted to BUFFER_SIZE
    int tail_idx;
    int head_idx;
    Syscall nodes[BUFFER_SIZE];
    struct mutex lock;
} MemoryQueue;

typedef struct ControlBuffer {
    MemoryQueue kernel_to_user;
    MemoryQueue user_to_kernel;
} ControlBuffer;

static ControlBuffer *global_ctl_buffer;
static DEFINE_MUTEX(ctl_buffer_mutex);


// ControlBuffer* control_buffer_new(void);
ControlBuffer* control_buffer_new(void);
void control_buffer_init(ControlBuffer *cb);
void control_buffer_free(ControlBuffer *cb);

int control_buffer_submit_syscall(ControlBuffer *cb, Syscall *syscall);


// Initialize ring buffer
MemoryQueue* mem_queue_new(void);
void mem_queue_init(MemoryQueue *queue);
void mem_queue_free(MemoryQueue *buf);

// Push syscall to the user-space
int mem_queue_push(MemoryQueue *buf, Syscall *syscall);
// Consume the syscall if applicable
Syscall* mem_queue_pop(MemoryQueue *buf);
// Print size of the ring buffer
int mem_queue_size(void);

#endif