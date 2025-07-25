#ifndef RSCALLER_CONTROL_BUFFER
#define RSCALLER_CONTROL_BUFFER

#include "types.h"

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

ControlBuffer* control_buffer_new(void);

static ControlBuffer *global_control_buffer;
int control_buffer_submit_syscall(Syscall *syscall);


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