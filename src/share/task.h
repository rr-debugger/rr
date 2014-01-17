/* -*- Mode: C++; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#ifndef TASK_H_
#define TASK_H_

#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/queue.h>
#include <sys/user.h>

#include <map>
#include <memory>
#include <set>

#include "fixedstack.h"
#include "trace.h"

struct Sighandlers;
class Task;
struct TaskGroup;

struct syscallbuf_hdr;
struct syscallbuf_record;

/* (There are various GNU and BSD extensions that define this, but
 * it's not worth the bother to sort those out.) */
typedef void (*sig_handler_t)(int);

class HasTaskSet {
public:
	typedef std::set<Task*> TaskSet;

	const TaskSet& task_set() { return tasks; }

	void insert_task(Task* t);
	void erase_task(Task* t);
protected:
	TaskSet tasks;
};

/**
 * Models the address space for a set of tasks.  This includes the set
 * of mapped pages, and the resources those mappings refer to.
 */
class AddressSpace : public HasTaskSet {
public:
	typedef std::shared_ptr<AddressSpace> shr_ptr;
	typedef std::set<AddressSpace*> Set;

	~AddressSpace() { sas.erase(this); }

	shr_ptr clone() {
		return shr_ptr(new AddressSpace());
	}

	static const Set& set() { return sas; }

	static shr_ptr create(Task* t) {
		shr_ptr as(new AddressSpace());
		as->insert_task(t);
		return as;
	}

private:
	AddressSpace() { sas.insert(this); }

	static Set sas;

	AddressSpace(const AddressSpace&);
	AddressSpace operator=(const AddressSpace&);
};

enum PseudosigType {
	ESIG_NONE,
	ESIG_SEGV_MMAP_READ, ESIG_SEGV_MMAP_WRITE, ESIG_SEGV_RDTSC,
	EUSR_EXIT, EUSR_SCHED, EUSR_NEW_RAWDATA_FILE,
	EUSR_SYSCALLBUF_FLUSH, EUSR_SYSCALLBUF_ABORT_COMMIT,
	EUSR_SYSCALLBUF_RESET,
	EUSR_UNSTABLE_EXIT,
};

enum EventType {
	EV_SENTINEL,
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
			PseudosigType no;
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
			byte* tmp_data_ptr;
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

enum CloneFlags {
	/**
	 * The child gets a semantic copy of all parent resources (and
	 * becomes a new task group).  This is the semantics of the
	 * fork() syscall.
	 */
	CLONE_SHARE_NOTHING = 0,
	/**
	 * Child will share the table of signal dispositions with its
	 * parent.
	 */
	CLONE_SHARE_SIGHANDLERS = 1 << 0,
	/** Child will join its parent's task group. */
	CLONE_SHARE_TASK_GROUP = 1 << 1,
	/** Child will share its parent's address space. */
	CLONE_SHARE_VM = 1 << 2,
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
class Task {
public:
	typedef std::map<pid_t, Task*> Map;

	~Task();

	/**
	 * Return a new Task cloned from this.  |flags| are a set of
	 * CloneFlags (see above) that determine which resources are
	 * shared or copied to the new child.  |new_tid| is the tid
	 * assigned to the new task by the kernel.  |new_rec_tid| is
	 * only relevant to replay, and is the pid that was assigned
	 * to the task during recording.
	 */
	Task* clone(int flags, pid_t new_tid, pid_t new_rec_tid = -1);

	/**
	 * Shortcut to the single |pending_event->desched.rec| when
	 * there's one desched event on the stack, and NULL otherwise.
	 * Exists just so that clients don't need to dig around in the
	 * event stack to find this record.
	 */
	const struct syscallbuf_record* desched_rec() const;

	/**
	 * An invariant of rr scheduling is that all process status
	 * changes happen as a result of rr resuming the execution of
	 * a task.  This is required to keep tracees in known states,
	 * preventing events from happening "behind rr's back".
	 * However, sometimes this seems to be unavoidable; one case
	 * is delivering some kinds of death signals.  When that
	 * situation occurs, notify the scheduler by calling this
	 * function: the effect is that the scheduler will always use
	 * |waitpid()| to schedule destabilized tasks, thereby
	 * assuming nothing about the destabilized tasks' statuses.
	 *
	 * Currently, instability is a one-way street; it's only been
	 * needed for death signals and exit_group() so far.  This
	 * helper (obviously) only acts at the task-group granularity,
	 * since it's not yet known how |killpg()| appears to
	 * ptracers.
	 */
	void destabilize_task_group();

	/**
	 * Stat |fd| in the context of this task's fd table, returning
	 * the result in |buf|.  Return true on success, false on
	 * error.
	 */
	bool fdstat(int fd, struct stat* buf);

	/**
	 * Return nonzero if |t| may not be immediately runnable,
	 * i.e., resuming execution and then |waitpid()|'ing may block
	 * for an unbounded amount of time.  When the task is in this
	 * state, the tracer must await a |waitpid()| notification
	 * that the task is no longer possibly-blocked before resuming
	 * its execution.
	 */
	bool may_be_blocked() const;

	/**
	 * Return the "next" task after this, in round-robin order by
	 * recorded pid.  The order of tasks returned by a sequence of
	 * |next_rounrobin()| calls is suitable for round-robin
	 * scheduling, in the steady state.
	 */
	Task* next_roundrobin() const;

	/**
	 * Call this after an execve() syscall finishes.  Emulate
	 * resource updates induced by the exec.
	 */
	void post_exec();

	/**
	 * Set the disposition and resethand semantics of |sig| to
	 * |sa|, overwriting whatever may already be there.
	 */
	void set_signal_disposition(int sig, const struct sigaction& sa);

	/**
	 * Call this after |sig| is delivered to this task.  Emulate
	 * sighandler updates induced by the signal delivery.
	 */
	void signal_delivered(int sig);

	/**
	 * Return nonzero if the disposition of |sig| in |table| isn't SIG_IGN
	 * or SIG_DFL, that is, if a user sighandler will be invoked when
	 * |sig| is received.
	 */
	bool signal_has_user_handler(int sig) const;

	/**
	 * Return the id of this task's thread group.
	 */
	pid_t tgid() const;

	/**
	 * Return the virtual memory mapping (address space) of this
	 * task.
	 */
	AddressSpace::shr_ptr vm() { return as; }

	/** Return an iterator at the beginning of the task map. */
	static Task::Map::const_iterator begin();

	/** Return the number of extant tasks. */
	static ssize_t count();

	/**
	 * Create and return the first tracee task.  It's hard-baked
	 * into rr that the first tracee is fork()ed, so create()
	 * "clones" the new task using fork() semantics.  |tid| and
	 * |rec_tid| are as for Task::clone().
	 */
	static Task* create(pid_t tid, pid_t rec_tid = -1);

	/** Return an iterator at the end of the task map. */
	static Task::Map::const_iterator end();

	/**
	 * Return the task created with |rec_tid|, or NULL if no such
	 * task exists.
	 */
	static Task* find(pid_t rec_tid);

	/* State only used during recording. */

	/* The running count of events that have been recorded for
	 * this task.  Starts at "1" to match with "global_time". */
	int thread_time;

	/* For convenience, the current top of |pending_events| if
	 * there are any.  If there aren't any pending, the top of the
	 * stack will be a placeholder event of type EV_SENTINEL.
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
	byte* scratch_ptr;
	ssize_t scratch_size;

	int event;
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
	/* True when the tracee has started using the syscallbuf, and
	 * the tracer will start receiving PTRACE_SECCOMP events for
	 * traced syscalls.  We don't make any attempt to guess at the
	 * OS's process/thread semantics; this flag goes on the first
	 * time rr sees a PTRACE_SECCOMP event from the task.
	 *
	 * NB: there must always be at least one traced syscall before
	 * any untraced ones; that's the magic "rrcall" the tracee
	 * uses to initialize its syscallbuf. */
	int seccomp_bpf_enabled;

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
	byte* untraced_syscall_ip;
	/* Start and end of the mapping of the syscallbuf code
	 * section, used to determine whether a tracee's $ip is in the
	 * lib. */
	byte* syscallbuf_lib_start;
	byte* syscallbuf_lib_end;
	/* Points at rr's mapping of the (shared) syscall buffer. */
	struct syscallbuf_hdr* syscallbuf_hdr;
	size_t num_syscallbuf_bytes;
	/* Points at the tracee's mapping of the buffer. */
	byte* syscallbuf_child;

private:
	Task(pid_t tid, pid_t rec_tid = -1);

	/* Points to the signal-hander table of this task.  If this
	 * task is a non-fork clone child, then the table will be
	 * shared with all its "thread" siblings.  Any updates made to
	 * that shared table are immediately visible to all sibling
	 * threads.
	 *
	 * fork and vfork children always get their own copies of the
	 * table.  And if this task exec()s, the table is copied and
	 * stripped of user sighandlers (see below). */
	std::shared_ptr<Sighandlers> sighandlers;
	/* The task group this belongs to. */
	std::shared_ptr<TaskGroup> task_group;
	/* The address space of this task. */
	std::shared_ptr<AddressSpace> as;

	Task(Task&) = delete;
	Task operator=(Task&) = delete;
};

/* (This function is an implementation detail that should go away in
 * favor of a |task_init()| pseudo-constructor that initializes state
 * shared across record and replay.) */
void push_placeholder_event(Task* t);

/**
 * Push/pop event tracking descheduling of |rec|.
 */
void push_desched(Task* t, const struct syscallbuf_record* rec);
void pop_desched(Task* t);

/**
 * Push/pop pseudo-sig events on the pending stack.  |no| is the enum
 * value of the pseudosig (see above), and |record_exec_info| is true
 * if the tracee's current state can be replicated during replay and
 * so should be recorded for consistency-checking purposes.
 */
enum { NO_EXEC_INFO = 0, HAS_EXEC_INFO };
void push_pseudosig(Task* t, PseudosigType no, int has_exec_info);
void pop_pseudosig(Task* t);

/**
 * Push/pop signal events on the pending stack.  |no| is the signum,
 * and |deterministic| is nonzero for deterministically-delivered
 * signals (see handle_signal.c).
 */
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
void push_syscall_interruption(Task* t, int no,
			       const struct user_regs_struct* args);
void pop_syscall_interruption(Task* t);

/**
 * Dump |t|'s stack of pending events to INFO log.
 */
void log_pending_events(const Task* t);

/**
 * Dump info about |ev| to INFO log.
 */
void log_event(const struct event* ev);

/**
 * Return a string naming |ev|'s type.
 */
const char* event_name(const struct event* ev);

#endif /* TASK_H_ */
