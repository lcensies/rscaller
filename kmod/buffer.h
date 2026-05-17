#ifndef RSCALLER_CONTROL_BUFFER
#define RSCALLER_CONTROL_BUFFER

#include "types.h"

#ifdef __USERSPACE__
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#endif

#ifndef __USERSPACE__
#include <linux/mutex.h>
#include <linux/completion.h>
#endif


#define BUFFER_SIZE 10

#define MAX_PARAM_BUF 4096
#define MAX_PARAMS    6

/* Per-slot per-param buffer — lives in shared memory, written by kmod for IN
 * params and by rsclient for OUT params. */
typedef struct {
    uint64_t user_ptr;          /* original userspace VA (for copy_to_user) */
    uint32_t size;              /* byte count of valid data in `data` */
    uint32_t direction;         /* PARAM_DIR_* */
    uint8_t  data[MAX_PARAM_BUF];
} ParamBuf;                     /* 8+4+4+4096 = 4112 bytes */

typedef struct {
    ParamBuf params[MAX_PARAMS];
} SlotBufs;                     /* 6 * 4112 = 24672 bytes */


typedef struct MemoryQueue{
    int size;
    int max_size;  /* defaulted to BUFFER_SIZE */
    int tail_idx;
    int head_idx;
    Syscall nodes[BUFFER_SIZE];
    /* NOTE: mutex/completion/retvals live in static arrays in buffer.c
     * (not here) so the shared mmap layout matches the Rust ControlBuffer. */
} MemoryQueue;

typedef struct ControlBuffer {
    MemoryQueue kernel_to_user;
    MemoryQueue user_to_kernel;
    SlotBufs    bufs[BUFFER_SIZE];  /* indexed by slot_idx */
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
