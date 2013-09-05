/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#ifndef TASK_H_
#define TASK_H_

#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/user.h>

#include "../external/tree.h"
#include "fixedstack.h"
#include "trace.h"

struct syscallbuf_hdr;
struct syscallbuf_record;

/* (There are various GNU and BSD extensions that define this, but
 * it's not worth the bother to sort those out.) */
typedef void (*sig_handler_t)(int);

/**
 * A signal-handler table.  The table stores the disposition of all
 * known signals, and additional metadata.  These tables are created
 * and manipulated through the sighandlers_() functions below.
 */
/*refcounted*/ struct sighandlers;

/**
 * Events are interesting occurrences during tracee execution which
 * are relevant for replay.  Most events correspond to tracee
 * execution, but some (a subset of "pseudosigs") save actions that
 * the *recorder* took on behalf of the tracee.
 */
struct event {
	enum {
		EV_NONE,
		/* Uses the .desched struct below. */
		EV_DESCHED,
		/* Uses .pseudosig. */
		EV_PSEUDOSIG,
		/* Use .signal. */
		EV_SIGNAL,
		EV_SIGNAL_DELIVERY,
		EV_SIGNAL_HANDLER,
		/* Use .syscall. */
		EV_SYSCALL,
		EV_SYSCALL_INTERRUPTION,
	} type;
	union {
		/**
		 * Desched events track the fact that a tracee's
		 * desched-event notification fired during a may-block
		 * buffered syscall, which rr interprets as the
		 * syscall actually blocking (for a potentially
		 * unbounded amount of time).  After the syscall
		 * exits, rr advances the tracee to where the desched
		 * is "disarmed" by the tracee.
		 */
		struct {
			enum { IN_SYSCALL,
			       DISARMING_DESCHED_EVENT,
			       DISARMED_DESCHED_EVENT
			} state;
			/* Record of the syscall that was interrupted
			 * by a desched notification.  It's legal to
			 * reference this memory /while the desched is
			 * being processed only/, because |t| is in
			 * the middle of a desched, which means it's
			 * successfully allocated (but not yet
			 * committed) this syscall record. */
			const struct syscallbuf_record* rec;
		} desched;

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
			/* Nonzero when this signal has been delivered
			 * by a ptrace() request. */
			int delivered;
		} signal;

		/**
		 * Syscall events track syscalls through entry into
		 * the kernel, processing in the kernel, and exit from
		 * the kernel.
		 */
		struct {
			enum { NO_SYSCALL,
			       ENTERING_SYSCALL, PROCESSING_SYSCALL,
			       EXITING_SYSCALL } state;
			/* Syscall number. */
			int no;
			/* When tasks enter syscalls that may block
			 * and so must be prepared for a
			 * context-switch, and the syscall params
			 * include (in)outparams that point to
			 * buffers, we need to redirect those
			 * arguments to scratch memory.  This allows
			 * rr to serialize execution of what may be
			 * multiple blocked syscalls completing
			 * "simulatenously" (from rr's perspective).
			 * After the syscall exits, we restore the
			 * data saved in scratch memory to the
			 * original buffers.
			 *
			 * Then during replay, we simply restore the
			 * saved data to the tracee's passed-in buffer
			 * args and continue on.
			 *
			 * The array |saved_arg_ptr| stores the
			 * original callee pointers that we replaced
			 * with pointers into the syscallbuf.
			 * |tmp_data_num_bytes| is the number of bytes
			 * we'll be saving across *all* buffer
			 * outparams.  (We can save one length value
			 * because all the tmp pointers into scratch
			 * are contiguous.)  |tmp_data_ptr| /usually/
			 * points at |scratch_ptr|, except ...
			 *
			 * ... a fly in this ointment is may-block
			 * buffered syscalls.  If a task blocks in one
			 * of those, it will look like it just entered
			 * a syscall that needs a scratch buffer.
			 * However, it's too late at that point to
			 * fudge the syscall args, because processing
			 * of the syscall has already begun in the
			 * kernel.  But that's OK: the syscallbuf code
			 * has already swapped out the original
			 * buffer-pointers for pointers into the
			 * syscallbuf (which acts as its own scratch
			 * memory).  We just have to worry about
			 * setting things up properly for replay.
			 *
			 * The descheduled syscall will "abort" its
			 * commit into the syscallbuf, so the outparam
			 * data won't actually be saved there (and
			 * thus, won't be restored during replay).
			 * During replay, we have to restore them like
			 * we restore the non-buffered-syscall scratch
			 * data.
			 *
			 * What we do is add another level of
			 * indirection to the "scratch pointer",
			 * through |tmp_data_ptr|.  Usually that will
			 * point at |scratch_ptr|, for unbuffered
			 * syscalls.  But for desched'd buffered ones,
			 * it will point at the region of the
			 * syscallbuf that's being used as "scratch".
			 * We'll save that region during recording and
			 * restore it during replay without caring
			 * which scratch space it points to.
			 *
			 * (The recorder code has to be careful,
			 * however, not to attempt to copy-back
			 * syscallbuf tmp data to the "original"
			 * buffers.  The syscallbuf code will do that
			 * itself.) */
			FIXEDSTACK_DECL(, void*, 5) saved_args;
			void* tmp_data_ptr;
			int tmp_data_num_bytes;

			/* Nonzero when this syscall was restarted
			 * after a signal interruption. */
			int is_restart;
			/* The original (before scratch is set up)
			 * arguments to the syscall passed by the
			 * tracee.  These are used to detect restarted
			 * syscalls. */
			struct user_regs_struct regs;
		} syscall;
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

	/* Points to the signal-hander table of this task.  If this
	 * task is a non-fork clone child, then the table will be
	 * shared with all its "thread" siblings.  Any updates made to
	 * that shared table are immediately visible to all sibling
	 * threads.
	 *
	 * fork and vfork children always get their own copies of the
	 * table.  And if this task exec()s, the table is copied and
	 * stripped of user sighandlers (see below). */
	/*refcounted*/struct sighandlers* sighandlers;

	/* For convenience, the current top of |pending_events| if
	 * there are any.  If there aren't any pending, the top of the
	 * stack will be a placeholder event of type EV_NONE.
	 *
	 * Never reassign this pointer directly; use the
	 * push_*()/pop_*() helpers below. */
	struct event* ev;
	/* The current stack of events being processed. */
	FIXEDSTACK_DECL(, struct event, 16) pending_events;

	/* Whether switching away from this task is allowed in its
	 * current state.  Some operations must be completed
	 * atomically and aren't switchable. */
	int switchable;
	/* Number of times this context has been scheduled in a row,
	 * which approximately corresponds to the number of events
	 * it's processed in succession.  The scheduler maintains this
	 * state and uses it to make scheduling decisions. */
	int succ_event_counter;
	/* Nonzero when any assumptions made about the status of this
	 * process have been invalidated, and must be re-established
	 * with a waitpid() call. */
	int unstable;

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
	 * Syscalls can "nest" due to signal handlers.  If a syscall A
	 * is interrupted by a signal, and the sighandler calls B,
	 * then we can have scratch buffers set up for args of both A
	 * and B.  In linux, B won't actually re-enter A; A is exited
	 * with a "will-restart" error code and its args are saved for
	 * when (or if) it's restarted after the signal.  But that
	 * doesn't really matter wrt scratch space.  (TODO: in the
	 * future, we may be able to use that fact to simplify
	 * things.)
	 *
	 * Because of nesting, at first blush it seems we should push
	 * scratch allocations onto a stack and pop them as syscalls
	 * (or restarts thereof) complete.  But under a critical
	 * assumption, we can actually skip that.  The critical
	 * assumption is that the kernel writes its (in)outparams
	 * atomically wrt signal interruptions, and only writes them
	 * on successful exit.  Each syscall will complete in stack
	 * order, and it's invariant that the syscall processors must
	 * only write back to user buffers *only* the data that was
	 * written by the kernel.  So as long as the atomicity
	 * assumption holds, the completion of syscalls higher in the
	 * event stack may overwrite scratch space, but the completion
	 * of each syscall will overwrite those overwrites again, and
	 * that over-overwritten data is exactly and only what we'll
	 * write back to the tracee.
	 *
	 * |scratch_ptr| points at the mapped address in the child,
	 * and |size| is the total available space. */
	void *scratch_ptr;
	size_t scratch_size;

	int event;
	/* Shortcut pointer to the single |pending_event->desched.rec|
	 * when there's one desched event on the stack, and NULL
	 * otherwise.  Exists just so that clients don't need to dig
	 * around in the event stack to find this record. */
	const struct syscallbuf_record* desched_rec;
	/* Nonzero after the trace recorder has flushed the
	 * syscallbuf.  When this happens, the recorder must prepare a
	 * "reset" of the buffer, to zero the record count, at the
	 * next available slow (taking |desched| into
	 * consideration). */
	int flushed_syscallbuf;
	/* This bit is set when code wants to prevent the syscall
	 * record buffer from being reset when it normally would be.
	 * Currently, the desched'd syscall code uses this. */
	int delay_syscallbuf_reset;
	/* This bit is set when code wants the syscallbuf to be
	 * "synthetically empty": even if the record counter is
	 * nonzero, it should not be flushed.  Currently, the
	 * desched'd syscall code uses this along with
	 * |delay_syscallbuf_reset| above to keep the syscallbuf
	 * intact during possibly many "reentrant" events. */
	int delay_syscallbuf_flush;

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
 * Return nonzero if |t| may not be immediately runnable, i.e.,
 * resuming execution and then |waitpid()|'ing may block for an
 * unbounded amount of time.  When the task is in this state, the
 * tracer must await a |waitpid()| notification that the task is no
 * longer possibly-blocked before resuming its execution.
 */
int task_may_be_blocked(struct task* t);

/* (This function is an implementation detail that should go away in
 * favor of a |task_init()| pseudo-constructor that initializes state
 * shared across record and replay.) */
void push_placeholder_event(struct task* t);

/**
 * Push/pop event tracking descheduling of |rec|.
 */
void push_desched(struct task* t, const struct syscallbuf_record* rec);
void pop_desched(struct task* t);

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
void push_pending_signal(struct task* t, int no, int deterministic);
void pop_signal_delivery(struct task* t);
void pop_signal_handler(struct task* t);

/**
 * Push/pop syscall events on the pending stack.  |no| is the syscall
 * number.
 */
void push_syscall(struct task* t, int no);
void pop_syscall(struct task* t);

/**
 * Pop the syscall interruption event from the top of the stack.
 */
void pop_syscall_interruption(struct task* t);

/**
 * Dump |t|'s stack of pending events to INFO log.
 */
void log_pending_events(const struct task* t);

/**
 * Dump info about |ev| to INFO log.
 */
void log_event(const struct event* ev);

/**
 * Return a string naming |ev|'s type.
 */
const char* event_name(const struct event* ev);

/**
 * Create and return a new sighandler table with all signals set to
 * disposition SIG_DFL and resethand = 0.
 *
 * The returned table has refcount 1, so the caller must
 * sighandlers_unref() it to free it.
 */
struct sighandlers* sighandlers_new();
/**
 * Copy all the sighandlers and metadata from the caller's process
 * into |table|, overwriting whatever data was already in |table|.
 * Callers should be sure they know what they're doing before calling
 * this.
 */
void sighandlers_init_from_current_process(struct sighandlers* table);
/**
 * Return nonzero if the disposition of |sig| in |table| isn't SIG_IGN
 * or SIG_DFL, that is, if a user sighandler will be invoked when
 * |sig| is received.
 */
int sighandlers_has_user_handler(const struct sighandlers* table, int sig);
/**
 * Return nonzero if |sig| has SA_RESETHAND behavior, as stored by
 * sighandlers_set_disposition() below.  SA_RESETHAND behavior is
 * defined as:
 *
 *   Restore the signal action to the default [Ed: SIG_DFL] upon entry
 *   to the signal handler.  This flag is only meaningful when
 *   establishing a signal handler.
 */
int sighandlers_is_resethand(const struct sighandlers* table, int sig);
/**
 * Set the disposition and resethand semantics of |sig| in |table|,
 * overwriting whatever may already be there.
 */
enum { NO_RESET = 0, RESET_HANDLER };
void sighandlers_set_disposition(struct sighandlers* table, int sig,
				 sig_handler_t disp, int resethand);
/**
 * Return an exact copy of |from|, except with refcount 1 (regardless
 * of what |from|'s refcount is).  That is, return a freshly allocated
 * copy of |from|.
 *
 * The caller must sighandlers_unref() the returned table to free it.
 */
struct sighandlers* sighandlers_copy(struct sighandlers* from);
/**
 * Add another reference to |table|, so that one more
 * sighandlers_unref() is required to free it.  |table| is returned
 * for convenience.
 */
struct sighandlers* sighandlers_ref(struct sighandlers* table);
/**
 * For each signal in |table| such that sighandlers_has_user_handler()
 * returns nonzero, reset the disposition of that signal to SIG_DFL,
 * and clear the resethand flag if it's nonzero.  SIG_IGN signals are
 * not modified.
 *
 * (After an exec() call copies the original sighandler table, this is
 * the operation required by POSIX to initialize that table copy.)
 */
void sighandlers_reset_user_handlers(struct sighandlers* table);
/**
 * Remove a reference to |*table|.  If the removed reference was the
 * last, free the memory pointed at |*table|.  In any case, set
 * |*table| to NULL before return.
 */
void sighandlers_unref(struct sighandlers** table);

#endif /* TASK_H_ */
