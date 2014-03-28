/* -*- Mode: C++; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#ifndef EVENT_H_
#define EVENT_H_

#include <sys/user.h>

#include "fixedstack.h"

struct Task;

enum EventType {
	EV_SENTINEL,
	/* No associated data. */
	EV_EXIT,
	EV_EXIT_SIGHANDLER,
	EV_INTERRUPTED_SYSCALL_NOT_RESTARTED,
	EV_NOOP,
	EV_SCHED,
	EV_SEGV_RDTSC,
	EV_SYSCALLBUF_FLUSH,
	EV_SYSCALLBUF_ABORT_COMMIT,
	EV_SYSCALLBUF_RESET,
	EV_UNSTABLE_EXIT,
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
};

enum DeschedState { IN_SYSCALL,
		    DISARMING_DESCHED_EVENT, DISARMED_DESCHED_EVENT };

enum SyscallState { NO_SYSCALL,
		    ENTERING_SYSCALL, PROCESSING_SYSCALL, EXITING_SYSCALL };

/**
 * Events are interesting occurrences during tracee execution which
 * are relevant for replay.  Most events correspond to tracee
 * execution, but some (a subset of "pseudosigs") save actions that
 * the *recorder* took on behalf of the tracee.
 */
struct event {
	EventType type;
	/* When replaying a pseudosignal is expected to leave the
	 * tracee in the same execution state as during replay, the
	 * event has meaningful execution info, and it should be
	 * recorded for checking.  But some pseudosigs aren't recorded
	 * in the same tracee state they'll be replayed, so the tracee
	 * exeuction state isn't meaningful. */
	bool has_exec_info;
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
			DeschedState state;
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
			SyscallState state;
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
			ssize_t tmp_data_num_bytes;

			/* Nonzero when this syscall was restarted
			 * after a signal interruption. */
			int is_restart;
			/* The original (before scratch is set up)
			 * arguments to the syscall passed by the
			 * tracee.  These are used to detect restarted
			 * syscalls. */
			struct user_regs_struct regs;
			/* If this is a descheduled buffered syscall,
			 * points at the record for that syscall. */
			const struct syscallbuf_record* desched_rec;
		} syscall;
	};
};

/**
 * Push an event that doesn't have a more specific push_*()/pop_*()
 * helper pair below.  Pass |HAS_EXEC_INFO| if the event is at a
 * stable execution point that we'll reach during replay too.
 */
enum { NO_EXEC_INFO = 0, HAS_EXEC_INFO };
void push_event(Task* t, EventType type, int has_exec_info);
void pop_event(Task* t, EventType expected_type);

/* (This function is an implementation detail that should go away in
 * favor of a |task_init()| pseudo-constructor that initializes state
 * shared across record and replay.) */
void push_placeholder_event(Task* t);

/**
 * Push/pop no-op event.
 */
void push_noop(Task* t);
void pop_noop(Task* t);

/**
 * Push/pop event tracking descheduling of |rec|.
 */
void push_desched(Task* t, const struct syscallbuf_record* rec);
void pop_desched(Task* t);

/**
 * Push/pop signal events on the pending stack.  |no| is the signum,
 * and |deterministic| is nonzero for deterministically-delivered
 * signals (see handle_signal.c).
 */
enum { NONDETERMINISTIC_SIG = 0, DETERMINISTIC_SIG = 1 };
void push_pending_signal(Task* t, int no, int deterministic);
void pop_signal_delivery(Task* t);
void pop_signal_handler(Task* t);

/**
 * Push/pop syscall events on the pending stack.  |no| is the syscall
 * number.
 */
void push_syscall(Task* t, int no);
void pop_syscall(Task* t);

/**
 * Push/pop syscall interruption events.
 *
 * During recording, only descheduled buffered syscalls /push/ syscall
 * interruptions; all others are detected at exit time and transformed
 * into syscall interruptions from the original, normal syscalls.
 *
 * During replay, we push interruptions to know when we need to
 * emulate syscall entry, since the kernel won't have set things up
 * for the tracee to restart on its own.
 */
void push_syscall_interruption(Task* t, int no);
void pop_syscall_interruption(Task* t);

/** Return nonzero if |type| is one of the EV_*SYSCALL* events. */
int is_syscall_event(int type);

/**
 * Dump |t|'s stack of pending events to INFO log.
 */
void log_pending_events(const Task* t);

/**
 * Dump info about |ev| to INFO log.
 */
void log_event(const struct event* ev);

/**
 * Return the symbolic name of |state|, or "???state" if unknown.
 */
const char* statename(int state);

/**
 * Return a string describing |event|, or some form of "???" if
 * |event| is unknown.
 */
const char* strevent(int event);

/**
 * Return a string naming |ev|'s type.
 */
const char* event_name(const struct event& ev);

#endif // EVENT_H_
