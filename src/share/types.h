/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#ifndef TYPES_H_
#define TYPES_H_

#include <stddef.h>
#include <stdio.h>
#include <stdint.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/user.h>

#include "../external/tree.h"

#define __unused __attribute__((unused))

#define CHECK_ALIGNMENT(addr) 	assert(((long int)(addr) & 0x3) == 0)
#define PAGE_ALIGN(length)		((length + PAGE_SIZE - 1) & PAGE_MASK)

#define PTR_SIZE		(sizeof(void*))
#define INT_SIZE		(sizeof(int))

#define UUL_COLUMN_SIZE 	20
#define LI_COLUMN_SIZE 		11

typedef enum { FALSE = 0, TRUE = 1 } bool;

typedef unsigned char byte;

struct syscallbuf_hdr;

/**
 * A trace_frame is one "trace event" from a complete trace.  During
 * recording, a trace_frame is recorded upon each significant event,
 * for example a context-switch or syscall.  During replay, a
 * trace_frame represents a "next state" that needs to be transitioned
 * into, and the information recorded in the frame dictates the nature
 * of the transition.
 */
struct trace_frame
{
	/* meta information */
	uint32_t global_time;
	uint32_t thread_time;
	pid_t tid;
	int stop_reason;
	int state;

	/* hpc data */
	uint64_t hw_interrupts;
	uint64_t page_faults;
	uint64_t rbc;
	uint64_t insts;

	/* register values */
	struct user_regs_struct recorded_regs;
};


struct context {
	struct trace_frame trace;
	struct hpc_context* hpc;

	/* recorder */
	int exec_state;
	int event;
	int allow_ctx_switch;
	/* Nonzero when this context has been interrupted by a desched
	 * event while making a buffered may-block syscall (and
	 * remained blocked in the syscall).  When this is the case,
	 * we have to allow switching out this context to make
	 * progress, in general.  We also need to record some extra
	 * trace data to ensure replay doesn't diverge. */
	int desched;
	/* Nonzero after the trace recorder has flushed the
	 * syscallbuf.  When this happens, the recorder must prepare a
	 * "reset" of the buffer, to zero the record count, at the
	 * next available slow (taking |desched| into
	 * consideration). */
	int flushed_syscallbuf;
	void *scratch_ptr;
	int scratch_size;
	int switch_counter;
	int last_syscall;
	/* Nonzero when the current syscall (saved to |last_syscall|
	 * above) will restart.  When this is the case, we have to
	 * advance to the syscall "entry" point using PTRACE_SYSCALL;
	 * PTRACE_CONT has been observed to miss the syscall re-entry
	 * point, for not-well-understand reasons. */
	int will_restart;

	/* When tasks enter syscalls that may block and so must be
	 * prepared for a context-switch, and the syscall params
	 * include (in)outparams that point to buffers, we need to
	 * redirect those arguments to scratch memory.  This allows rr
	 * to serialize execution of what may be multiple blocked
	 * syscalls completing "simulatenously" (from rr's
	 * perspective).  After the syscall exits, we restore the data
	 * saved in scratch memory to the original buffers.
	 *
	 * Then during replay, we simply restore the saved data to the
	 * tracee's passed-in buffer args and continue on.
	 *
	 * The array |saved_arg_ptr| stores the original callee
	 * pointers that we replaced with pointers into the
	 * syscallbuf.  |tmp_data_num_bytes| is the number of bytes
	 * we'll be saving across *all* buffer outparams.  (We can
	 * save one length value because all the tmp pointers into
	 * scratch are contiguous.)  |tmp_data_ptr| /usually/ points
	 * at |scratch_ptr|, except ...
	 *
	 * ... a fly in this ointment is may-block buffered syscalls.
	 * If a task blocks in one of those, it will look like it just
	 * entered a syscall that needs a scratch buffer.  However,
	 * it's too late at that point to fudge the syscall args,
	 * because processing of the syscall has already begun in the
	 * kernel.  But that's OK: the syscallbuf code has already
	 * swapped out the original buffer-pointers for pointers into
	 * the syscallbuf (which acts as its own scratch memory).  We
	 * just have to worry about setting things up properly for
	 * replay.
	 *
	 * The descheduled syscall will "abort" its commit into the
	 * syscallbuf, so the outparam data won't actually be saved
	 * there (and thus, won't be restored during replay).  During
	 * replay, we have to restore them like we restore the
	 * non-buffered-syscall scratch data.
	 *
	 * What we do is add another level of indirection to the
	 * "scratch pointer", through |tmp_data_ptr|.  Usually that
	 * will point at |scratch_ptr|, for unbuffered syscalls.  But
	 * for desched'd buffered ones, it will point at the region of
	 * the syscallbuf that's being used as "scratch".  We'll save
	 * that region during recording and restore it during replay
	 * without caring which scratch space it points to.
	 *
	 * (The recorder code has to be careful, however, not to
	 * attempt to copy-back syscallbuf tmp data to the "original"
	 * buffers.  The syscallbuf code will do that itself.) */
	void* saved_arg_ptr[3];
	int next_saved_arg;
	void* tmp_data_ptr;
	int tmp_data_num_bytes;

	/* The child's desched counter event fd number, and our local
	 * dup. */
	int desched_fd, desched_fd_child;

	/* shared */
	struct user_regs_struct child_regs;
	FILE *inst_dump;
	/* This is always the "real" tid of the tracee. */
	pid_t child_tid;
	/* This is always the recorded tid of the tracee.  During
	 * recording, it's synonymous with child_tid, and during
	 * replay it's the tid that was recorded. */
	pid_t rec_tid;
	int child_mem_fd;
	int child_sig;
	int status;

	/* The instruction pointer from which untraced syscalls will
	 * originate, used to determine whether a syscall is being
	 * made by the syscallbuf wrappers or not. */
	void* untraced_syscall_ip;
	/* Start and end of the mapping of the syscallbuf code
	 * section, used to determine whether a tracee's $ip is in the
	 * lib. */
	void* syscallbuf_lib_start;
	void* syscallbuf_lib_end;
	/* Points at rr's mapping of the (shared) syscall buffer
	 * itself. */
	struct syscallbuf_hdr* syscallbuf_hdr;
	/* Points at the tracee's mapping of the buffer. */
	void* syscallbuf_child;

	RB_ENTRY(context) entry;
};

/* XXX/pedant more accurately called a "mapped /region/", since we're
 * not mapping entire files, necessarily. */
struct mmapped_file {
	/* Global trace time when this region was mapped. */
	int time;
	int tid;
	/* Did we save a copy of the mapped region in the trace
	 * data? */
	int copied;

	char filename[1024];
	struct stat stat;

	/* Bounds of mapped region. */
	void* start;
	void* end;
};

/**
 * command line arguments for rr
 */

#define INVALID			0
#define RECORD			1
#define REPLAY			2

#define DUMP_ON_NONE 	-1001
#define DUMP_ON_ALL 	1000

#define DUMP_AT_NONE 	-1

#define CHECKSUM_NONE			-3
#define CHECKSUM_SYSCALL		-2
#define CHECKSUM_ALL			-1

struct flags {
	/* Max counter value before the scheduler interrupts a tracee. */
	int max_rbc;
	/* Max number of trace events before the scheduler
	 * de-schedules a tracee. */
	int max_events;
	int option;
	bool redirect;
	bool use_syscall_buffer;
	char *syscall_buffer_lib_path;
	int dump_on;	// event
	int dump_at;	// global time
	int checksum;
	/* Nonzero when we're replaying without a controlling debugger. */
	int autopilot;
	/* IP port to listen on for debug connections. */
	int dbgport;
	/* Number of seconds to wait after startup, before starting
	 * "real work". */
	int wait_secs;
};

#endif /* TYPES_H_ */
