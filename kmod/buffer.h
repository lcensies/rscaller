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
#include <linux/completion.h>
#endif


#define BUFFER_SIZE 10


typedef struct MemoryQueue{
    int size;
    int max_size;  /* defaulted to BUFFER_SIZE */
    int tail_idx;
    int head_idx;
    Syscall nodes[BUFFER_SIZE];
#ifndef __USERSPACE__
    struct mutex lock;
    struct completion slot_completions[BUFFER_SIZE];
    long slot_retvals[BUFFER_SIZE];
#endif
} MemoryQueue;

typedef struct ControlBuffer {
    MemoryQueue kernel_to_user;
    MemoryQueue user_to_kernel;
} ControlBuffer;

/* Bug C fix: extern declarations — defined once in buffer.c */
extern ControlBuffer *global_ctl_buffer;
#ifndef __USERSPACE__
extern struct mutex ctl_buffer_mutex;
#endif


ControlBuffer* control_buffer_new(void);
void control_buffer_init(ControlBuffer *cb);
void control_buffer_free(ControlBuffer *cb);

/* Returns slot index (>=0) on success, -1 on error */
int control_buffer_submit_syscall(ControlBuffer *cb, Syscall *syscall);

#ifndef __USERSPACE__
/* Block until userspace writes return value for slot at slot_idx */
long control_buffer_wait_result(ControlBuffer *cb, int slot_idx);
/* Called by rsclient path to signal completion */
void control_buffer_complete(ControlBuffer *cb, int slot_idx, long retval);
#endif


/* Initialize ring buffer */
MemoryQueue* mem_queue_new(void);
void mem_queue_init(MemoryQueue *queue);
void mem_queue_free(MemoryQueue *buf);

/* Push syscall to the user-space */
int mem_queue_push(MemoryQueue *buf, Syscall *syscall);
/* Consume the syscall if applicable */
Syscall* mem_queue_pop(MemoryQueue *buf);
/* Print size of the ring buffer */
int mem_queue_size(void);

#endif
