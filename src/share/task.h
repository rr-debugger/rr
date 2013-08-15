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
 * Events are interesting occurrences during tracee execution which
 * are relevant for replay.  Most events correspond to tracee
 * execution, but some (a subset of "pseudosigs" save actions that the
 * *recorder* took on behalf of the tracee.
 */
struct event {
	enum {
		EV_NONE, EV_PSEUDOSIG, EV_SIGNAL, EV_SYSCALL
	} type;
	union {
		/**
		 * Pseudosignals comprise three types of events: real,
		 * deterministic signals raised by tracee execution
		 * (e.g. tracees executing rdtsc); real signals raised
		 * because of rr implementation details, not the
		 * tracee (e.g., time-slice interrupts); and finally,
		 * "signals" from the recorder to the replayer that
		 * aren't real signals at all, but rather rr
		 * implementation details at the level of the tracer.
		 */
		struct {
			/* TODO: un-gnarl these names when we
			 * eliminate the duplication in trace.h */
			enum { ESIG_NONE,
			       ESIG_SEGV_MMAP_READ, ESIG_SEGV_MMAP_WRITE,
			       ESIG_SEGV_RDTSC,
			       EUSR_EXIT, EUSR_SCHED, EUSR_NEW_RAWDATA_FILE,
			       EUSR_INIT_SCRATCH_MEM,
			       EUSR_SYSCALLBUF_FLUSH,
			       EUSR_SYSCALLBUF_ABORT_COMMIT,
			       EUSR_SYSCALLBUF_RESET,
			       EUSR_ARM_DESCHED,
			       EUSR_DISARM_DESCHED,
			} no;
			/* When replaying a pseudosignal is expected
			 * to leave the tracee in the same execution
			 * state as during replay, the event has
			 * meaningful execution info, and it should be
			 * recorded for checking.  But some pseudosigs
			 * aren't recorded in the same tracee state
			 * they'll be replayed, so the tracee
			 * exeuction state isn't meaningful. */
			int has_exec_info;
		} pseudosig;

		/**
		 * Syscall events track syscalls through entry into
		 * the kernel, processing in the kernel, and exit from
		 * the kernel.
		 */
		struct {
			/* TODO: |RUNNABLE| is a temporary guest in
			 * this enum while refactorings are in
			 * progress. */
			enum { NO_SYSCALL,
			       RUNNABLE = 1,
			       ENTERING_SYSCALL, PROCESSING_SYSCALL,
			       EXITING_SYSCALL } state;
			/* Syscall number. */
			int no;
		} syscall;

		/**
		 * Signal events track signals through the delivery
		 * phase, and if the signal finds a sighandler, on to
		 * the end of the handling face.
		 */
		struct {
			/* Signal number. */
			int no;
			/* Nonzero if this signal will be
			 * deterministically raised as the side effect
			 * of retiring an instruction during replay,
			 * for example |load $r 0x0| deterministically
			 * raises SIGSEGV. */
			int deterministic;
		} signal;
	};
};

/**
 * A "task" is a task in the linux usage: the unit of scheduling.  (OS
 * people sometimes call this a "thread control block".)  Multiple
 * tasks may share the same address space and file descriptors, in
 * which case they're commonly called "threads".  Or two tasks may
 * have their own address spaces and file descriptors, in which case
 * they're called "processes".  Both look the same to rr (on linux),
 * so no distinction is made here.
 */
struct task {
	/* State only used during recording. */

	/* For convenience, the current top of |pending_events| if
	 * there are any, or NULL.  Never reassign this pointer
	 * directly; use the push_*()/pop_*() helpers below. */
	struct event* ev;
	/* The current stack of events being processed. */
	FIXEDSTACK_DECL(, struct event, 2) pending_events;

	/* Whether switching away from this task is allowed in its
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

	int exec_state;
	int event;
	/* Record of the syscall that was interrupted by a desched
	 * notification.  It's legal to reference this memory /while
	 * the desched is being processed only/, because |t| is in
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

	RB_ENTRY(task) entry;
};

/**
 * Push/pop pseudo-sig events on the pending stack.  |no| is the enum
 * value of the pseudosig (see above), and |record_exec_info| is true
 * if the tracee's current state can be replicated during replay and
 * so should be recorded for consistency-checking purposes.
 */
enum { NO_EXEC_INFO = 0, HAS_EXEC_INFO };
void push_pseudosig(struct task* t, int no, int has_exec_info);
void pop_pseudosig(struct task* t);

/**
 * Push/pop signal events on the pending stack.  |no| is the signum,
 * and |deterministic| is nonzero for deterministically-delivered
 * signals (see handle_signal.c).
 */
void push_signal(struct task* t, int no, int deterministic);
void pop_signal(struct task* t);

/**
 * Push/pop syscall events on the pending stack.  |no| is the syscall
 * number.
 */
void push_syscall(struct task* t, int no);
void pop_syscall(struct task* t);

#endif /* TASK_H_ */
