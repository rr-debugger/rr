/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#ifndef TASK_H_
#define TASK_H_

#include <stddef.h>
#include <stdint.h>
#include <sys/user.h>

#include "../external/tree.h"
#include "fixedstack.h"
#include "trace.h"

struct syscallbuf_hdr;
struct syscallbuf_record;

/**
 * A "context" is a task, in the linux usage: the unit of scheduling.
 * (OS people sometimes call this a "thread control block".)  Multiple
 * tasks may share the same address space and file descriptors, in
 * which case they're commonly called "threads".  Or two tasks may
 * have their own address spaces and file descriptors, in which case
 * they're called "processes".  Both look the same to rr (on linux),
 * so no distinction is made here.
 */
struct context {
	/* State only used during recording. */

	/* Whether switching away from this context is allowed in its
	 * current state.  Some operations must be completed
	 * atomically and aren't switchable. */
	int switchable;
	/* Number of times this context has been scheduled in a row,
	 * which approximately corresponds to the number of events
	 * it's processed in succession.  The scheduler maintains this
	 * state and uses it to make scheduling decisions. */
	int succ_event_counter;

	/* Imagine that task A passes buffer |b| to the read()
	 * syscall.  Imagine that, after A is switched out for task B,
	 * task B then writes to |b|.  Then B is switched out for A.
	 * Since rr doesn't schedule the kernel code, the result is
	 * nondeterministic.  To avoid that class of replay
	 * divergence, we "redirect" (in)outparams passed to may-block
	 * syscalls, to "scratch memory".  The kernel writes to
	 * scratch deterministically, and when A (in the example
	 * above) exits its read() syscall, rr copies the scratch data
	 * back to the original buffers, serializing A and B in the
	 * example above.
	 *
	 * |scratch_ptr| points at the mapped address in the child,
	 * |size| is the total available space, and |len| is the *
	 * amount currently in use. */
	void *scratch_ptr;
	size_t scratch_size;
	size_t scratch_len;

	enum {
		RUNNABLE = 1,
		ENTERING_SYSCALL, PROCESSING_SYSCALL, EXITING_SYSCALL
	} exec_state;
	int event;
	/* Record of the syscall that was interrupted by a desched
	 * notification.  It's legal to reference this memory /while
	 * the desched is being processed only/, because |ctx| is in
	 * the middle of a desched, which means it's successfully
	 * allocated (but not yet committed) a syscall record. */
	const struct syscallbuf_record* desched_rec;
	/* Nonzero after the trace recorder has flushed the
	 * syscallbuf.  When this happens, the recorder must prepare a
	 * "reset" of the buffer, to zero the record count, at the
	 * next available slow (taking |desched| into
	 * consideration). */
	int flushed_syscallbuf;

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
	FIXEDSTACK_DECL(, void*, 5) saved_args;
	void* tmp_data_ptr;
	int tmp_data_num_bytes;

	/* The child's desched counter event fd number, and our local
	 * dup. */
	int desched_fd, desched_fd_child;

	/* State used only during replay. */

	int child_sig;

	/* State used during both recording and replay. */

	struct trace_frame trace;
	struct hpc_context* hpc;

	/* The most recent status of this task as returned by
	 * waitpid(). */
	int status;

	struct user_regs_struct regs;
	FILE *inst_dump;
	/* This is always the "real" tid of the tracee. */
	pid_t tid;
	/* This is always the recorded tid of the tracee.  During
	 * recording, it's synonymous with |tid|, and during replay
	 * it's the tid that was recorded. */
	pid_t rec_tid;
	int child_mem_fd;

	/* The instruction pointer from which untraced syscalls will
	 * originate, used to determine whether a syscall is being
	 * made by the syscallbuf wrappers or not. */
	void* untraced_syscall_ip;
	/* Start and end of the mapping of the syscallbuf code
	 * section, used to determine whether a tracee's $ip is in the
	 * lib. */
	void* syscallbuf_lib_start;
	void* syscallbuf_lib_end;
	/* Points at rr's mapping of the (shared) syscall buffer. */
	struct syscallbuf_hdr* syscallbuf_hdr;
	/* Points at the tracee's mapping of the buffer. */
	void* syscallbuf_child;

	RB_ENTRY(context) entry;
};

#endif /* TASK_H_ */
