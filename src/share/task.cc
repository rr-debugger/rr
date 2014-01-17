/* -*- Mode: C++; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

//#define DEBUGTAG "Task"

#include "task.h"

#include <stdlib.h>
#include <string.h>
#include <syscall.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <set>

#include "dbg.h"
#include "hpc.h"
#include "sys.h"
#include "util.h"

#include "../preload/syscall_buffer.h"

using namespace std;

static Task::Map tasks;

/*static*/ AddressSpace::Set AddressSpace::sas;

void
HasTaskSet::insert_task(Task* t)
{
	debug("adding %d to task set %p", t->tid, this);
	tasks.insert(t);
}

void
HasTaskSet::erase_task(Task* t) {
	debug("removing %d from task group %p", t->tid, this);
	tasks.erase(t);
}

/**
 * Stores the table of signal dispositions and metadata for an
 * arbitrary set of tasks.  Each of those tasks must own one one of
 * the |refcount|s while they still refer to this.
 */
struct Sighandler {
	Sighandler() : handler(SIG_DFL), resethand(false) { }
	Sighandler(const struct sigaction& sa) :
		handler((SA_SIGINFO & sa.sa_flags) ?
			(sig_handler_t)sa.sa_sigaction :
			sa.sa_handler),
		resethand(sa.sa_flags & SA_RESETHAND)
	{ }

	bool is_default() const {
		return SIG_DFL == handler && !resethand;
	}
	bool is_user_handler() const {
		static_assert((void*)1 == SIG_IGN, "");
		return (uintptr_t)handler & ~(uintptr_t)SIG_IGN;
	}

	sig_handler_t handler;
	bool resethand;
};
struct Sighandlers {
	typedef shared_ptr<Sighandlers> shr_ptr;

	shr_ptr clone() const {
		shr_ptr s(new Sighandlers());
		// NB: depends on the fact that Sighandler is for all
		// intents and purposes a POD type, though not
		// technically.
		memcpy(s->handlers, handlers, sizeof(handlers));
		return s;
	}

	Sighandler& get(int sig) {
		assert_valid(sig);
		return handlers[sig];
	}
	const Sighandler& get(int sig) const {
		assert_valid(sig);
		return handlers[sig];
	}

	void init_from_current_process() {
		for (int i = 0; i < ssize_t(ALEN(handlers)); ++i) {
			Sighandler& h = handlers[i];
			struct sigaction act;
			if (-1 == sigaction(i, NULL, &act)) {
				/* EINVAL means we're querying an
				 * unused signal number. */
				assert(EINVAL == errno);
				assert(h.is_default());
				continue;
			}
			h = Sighandler(act);
		}
	}

	/**
	 * For each signal in |table| such that is_user_handler() is
	 * true, reset the disposition of that signal to SIG_DFL, and
	 * clear the resethand flag if it's set.  SIG_IGN signals are
	 * not modified.
	 *
	 * (After an exec() call copies the original sighandler table,
	 * this is the operation required by POSIX to initialize that
	 * table copy.)
	 */
	void reset_user_handlers() {
		for (int i = 0; i < ssize_t(ALEN(handlers)); ++i) {
			Sighandler& h = handlers[i];
			// If the handler was a user handler, reset to
			// default.  If it was SIG_IGN or SIG_DFL,
			// leave it alone.
			if (h.is_user_handler()) {
				handlers[i] = Sighandler();
			}
		}
	}

	static void assert_valid(int sig) {
		assert(0 < sig && sig < ssize_t(ALEN(handlers)));
	}

	static shr_ptr create() {
		return shr_ptr(new Sighandlers());
	}

	Sighandler handlers[_NSIG];

private:
	Sighandlers() { }
	Sighandlers(const Sighandlers&);
	Sighandlers operator=(const Sighandlers&);
};

/**
 * Tracks a group of tasks with an associated ID, set from the
 * original "thread group leader", the child of |fork()| which became
 * the ancestor of all other threads in the group.  Each constituent
 * task must own a reference to this.
 */
struct TaskGroup : public HasTaskSet {
	typedef shared_ptr<TaskGroup> shr_ptr;

	void destabilize() {
		debug("destabilizing task group %d", tgid);
		for (auto it = task_set().begin(); it != task_set().end(); ++it) {
			Task* t = *it;
			t->unstable = 1;
			debug("  destabilized task %d", t->tid);
		}
	}

	static shr_ptr create(Task* t) {
		shr_ptr tg(new TaskGroup(t->tid));
		tg->insert_task(t);
		return tg;
	}

	pid_t tgid;

private:
	TaskGroup(pid_t tgid) : tgid(tgid) {
		debug("creating new task group %d", tgid);
	}
	TaskGroup(const TaskGroup&);
	TaskGroup operator=(const TaskGroup&);
};

static const char* event_type_name(int type)
{
	switch (type) {
	case EV_SENTINEL: return "(none)";
#define CASE(_t) case EV_## _t: return #_t
	CASE(DESCHED);
	CASE(PSEUDOSIG);
	CASE(SIGNAL);
	CASE(SIGNAL_DELIVERY);
	CASE(SIGNAL_HANDLER);
	CASE(SYSCALL);
	CASE(SYSCALL_INTERRUPTION);
#undef CASE
	default:
		fatal("Unknown event type %d", type);
	}
}

static int is_syscall_event(int type) {
	switch (type) {
	case EV_SYSCALL:
	case EV_SYSCALL_INTERRUPTION:
		return 1;
	default:
		return 0;
	}
}

/**
 * Detach |t| from rr and try hard to ensure any operations related to
 * it have completed by the time this function returns.
 */
static void detach_and_reap(Task* t)
{
	sys_ptrace_detach(t->tid);
	if (t->unstable) {
		log_warn("%d is unstable; not blocking on its termination",
			 t->tid);
		goto sleep_hack;
	}

	debug("Joining with exiting %d ...", t->tid);
	while (1) {
		int err = waitpid(t->tid, &t->status, __WALL);
		if (-1 == err && ECHILD == errno) {
			debug(" ... ECHILD");
			break;
		} else if (-1 == err) {
			assert_exec(t, EINTR == errno,
				    "waitpid(%d) returned -1, errno %d",
				    t->tid, errno);
		}
		if (err == t->tid && (WIFEXITED(t->status) || 
				      WIFSIGNALED(t->status))) {
			debug(" ... exited with status 0x%x", t->status);
			break;
		} else if (err == t->tid) {
			assert_exec(t, (PTRACE_EVENT_EXIT ==
					GET_PTRACE_EVENT(t->status)),
				    "waitpid(%d) return status %d",
				    t->tid, t->status);
		}
	}

sleep_hack:
	/* clone()'d tasks can have a pid_t* |ctid| argument that's
	 * written with the new task's pid.  That pointer can also be
	 * used as a futex: when the task dies, the original ctid
	 * value is cleared and a FUTEX_WAKE is done on the
	 * address. So pthread_join() is basically a standard futex
	 * wait loop.
	 *
	 * That means that the kernel writes shared memory behind rr's
	 * back, which can diverge replay.  The "real fix" for this is
	 * for rr to track access to shared memory, like the |ctid|
	 * location.  But until then, we (attempt to) let "time"
	 * resolve this memory race with the sleep() hack below.
	 *
	 * Why 4ms?  Because
	 *
	 * $ for i in $(seq 10); do (cd $rr/src/test/ && bash thread_cleanup.run) & done
	 *
	 * has been observed to fail when we sleep 3ms, but not when
	 * we sleep 4ms.  Yep, this hack is that horrible! */
	struct timespec ts;
	memset(&ts, 0, sizeof(ts));
	ts.tv_nsec = 4000000LL;
	nanosleep_nointr(&ts);
}

Task::Task(pid_t _tid, pid_t _rec_tid)
{
	// TODO: properly C++-ify me
	memset(this, 0, sizeof(*this));

	tid = _tid;
	rec_tid = _rec_tid > 0 ? _rec_tid : tid;
	thread_time = 1;
	child_mem_fd = sys_open_child_mem(this);
	// These will be initialized when the syscall buffer is.
	desched_fd = desched_fd_child = -1;

	push_placeholder_event(this);

	init_hpc(this);

	tasks[rec_tid] = this;
}

Task::~Task()
{
	debug("task %d (rec:%d) is dying ...", tid, rec_tid);

	assert(this == Task::find(rec_tid));
	// We expect tasks to usually exit by a call to exit() or
	// exit_group(), so it's not helpful to warn about that.
	if (FIXEDSTACK_DEPTH(&pending_events) > 2
	    || !(ev->type == EV_SYSCALL
		 && (SYS_exit == ev->syscall.no
		     || SYS_exit_group == ev->syscall.no))) {
		log_warn("%d still has pending events.  From top down:", tid);
		log_pending_events(this);
	}

	tasks.erase(rec_tid);
	task_group->erase_task(this);
	as->erase_task(this);

	destroy_hpc(this);
	close(child_mem_fd);
	close(desched_fd);
	munmap(syscallbuf_hdr, num_syscallbuf_bytes);

	detach_and_reap(this);

	debug("  dead");
}

Task*
Task::clone(int flags, pid_t new_tid, pid_t new_rec_tid)
{
	Task* t = new Task(new_tid, new_rec_tid);

	t->syscallbuf_lib_start = syscallbuf_lib_start;
	t->syscallbuf_lib_end = syscallbuf_lib_end;
	if (CLONE_SHARE_SIGHANDLERS & flags) {
		t->sighandlers = sighandlers;
	} else {
		auto sh = Sighandlers::create();
		t->sighandlers.swap(sh);
	}
	if (CLONE_SHARE_TASK_GROUP & flags) {
		t->task_group = task_group;
		task_group->insert_task(t);
	} else {
		auto tg = TaskGroup::create(t);
		t->task_group.swap(tg);
	}
	if (CLONE_SHARE_VM & flags) {
		t->as = as;
	} else {
		t->as = as->clone();
	}
	t->as->insert_task(t);
	return t;
}

const struct syscallbuf_record*
Task::desched_rec() const
{
	return (is_syscall_event(ev->type) ? ev->syscall.desched_rec :
		(EV_DESCHED == ev->type) ? ev->desched.rec : NULL);
}

void
Task::destabilize_task_group()
{
	task_group->destabilize();
}

bool
Task::fdstat(int fd, struct stat* buf)
{
	char path[PATH_MAX];
	snprintf(path, sizeof(path) - 1, "/proc/%d/fd/%d", tid, fd);
	AutoOpen backing_fd(path, O_RDONLY);
	return backing_fd >= 0 && 0 == fstat(backing_fd, buf);
}

bool
Task::may_be_blocked() const
{
	return (ev && ((EV_SYSCALL == ev->type
			&& PROCESSING_SYSCALL == ev->syscall.state)
		       || (EV_SIGNAL_DELIVERY == ev->type
			   && ev->signal.delivered)));
}

Task*
Task::next_roundrobin() const
{
	// XXX if this ever shows up on profiles, we can make Task
	// into an invasive doubly-linked list.
	auto it = tasks.find(rec_tid);
	assert(this == it->second);
	it = ++it == tasks.end() ? tasks.begin() : it;
	return it->second;
}

void
Task::post_exec()
{
	sighandlers = sighandlers->clone();
	sighandlers->reset_user_handlers();
	// TODO: create address space from post-exec /proc/maps
	auto a = AddressSpace::create(this);
	as.swap(a);
}

void
Task::set_signal_disposition(int sig, const struct sigaction& sa)
{
	sighandlers->get(sig) = Sighandler(sa);
}

void
Task::signal_delivered(int sig)
{
	Sighandler& h = sighandlers->get(sig);
	if (h.resethand) {
		h = Sighandler();
	}
}

bool
Task::signal_has_user_handler(int sig) const
{
	return sighandlers->get(sig).is_user_handler();
}

pid_t
Task::tgid() const
{
	return task_group->tgid;
}

/*static*/
Task::Map::const_iterator
Task::begin()
{
	return tasks.begin();
}

/*static*/ ssize_t
Task::count()
{
	return tasks.size();
}

/*static*/ Task*
Task::create(pid_t tid, pid_t rec_tid)
{
	assert(Task::count() == 0);

	Task* t = new Task(tid, rec_tid);
	// The very first task we fork inherits the signal
	// dispositions of the current OS process (which should all be
	// default at this point, but ...).  From there on, new tasks
	// will transitively inherit from this first task.
	auto sh = Sighandlers::create();
	sh->init_from_current_process();
	t->sighandlers.swap(sh);
	auto tg = TaskGroup::create(t);
	t->task_group.swap(tg);
	auto as = AddressSpace::create(t);
	t->as.swap(as);
	return t;
}

/*static*/
Task::Map::const_iterator
Task::end()
{
	return tasks.end();
}

/*static*/Task*
Task::find(pid_t rec_tid)
{
	auto it = tasks.find(rec_tid);
	return tasks.end() != it ? it->second : NULL;
}

/**
 * Push a new event onto |t|'s event stack of type |type|.
 */
static void push_new_event(Task* t, EventType type)
{
	struct event ev = { .type = EventType(type) };
	FIXEDSTACK_PUSH(&t->pending_events, ev);
	t->ev = FIXEDSTACK_TOP(&t->pending_events);
}

/**
 * Pop the pending-event stack and return the type of the previous top
 * element.
 */
static void pop_event(Task* t, int expected_type)
{
	int last_top_type;

	assert_exec(t, FIXEDSTACK_DEPTH(&t->pending_events) > 1,
		    "Attempting to pop sentinel event");

	last_top_type = FIXEDSTACK_POP(&t->pending_events).type;
	t->ev = FIXEDSTACK_TOP(&t->pending_events);
	assert_exec(t, expected_type == last_top_type,
		    "Should have popped event %s but popped %s instead",
		    event_type_name(expected_type),
		    event_type_name(last_top_type));
}

void push_placeholder_event(Task* t)
{
	assert(FIXEDSTACK_EMPTY(&t->pending_events));
	push_new_event(t, EV_SENTINEL);
}

void push_desched(Task* t, const struct syscallbuf_record* rec)
{
	assert_exec(t, !t->desched_rec(), "Must have zero or one desched");

	push_new_event(t, EV_DESCHED);
	t->ev->desched.state = IN_SYSCALL;
	t->ev->desched.rec = rec;
}

void pop_desched(Task* t)
{
	assert_exec(t, t->desched_rec(), "Must have desched_rec to pop");

	pop_event(t, EV_DESCHED);
}

void push_pseudosig(Task* t, PseudosigType no, int has_exec_info)
{
	push_new_event(t, EV_PSEUDOSIG);
	t->ev->pseudosig.no = no;
	t->ev->pseudosig.has_exec_info = has_exec_info;
}

void pop_pseudosig(Task* t)
{
	pop_event(t, EV_PSEUDOSIG);
}

void push_pending_signal(Task* t, int no, int deterministic)
{
	push_new_event(t, EV_SIGNAL);
	t->ev->signal.no = no;
	t->ev->signal.deterministic = deterministic;
}

void pop_signal_delivery(Task* t)
{
	pop_event(t, EV_SIGNAL_DELIVERY);
}

void pop_signal_handler(Task* t)
{
	pop_event(t, EV_SIGNAL_HANDLER);
}

void push_syscall(Task* t, int no)
{
	push_new_event(t, EV_SYSCALL);
	t->ev->syscall.no = no;
}

void pop_syscall(Task* t)
{
	pop_event(t, EV_SYSCALL);
}

void push_syscall_interruption(Task* t, int no,
			       const struct user_regs_struct* args)
{
	const struct syscallbuf_record* rec = t->desched_rec();

	assert_exec(t, rec || REPLAY == rr_flags()->option,
		    "Must be interrupting desched during recording");

	push_new_event(t, EV_SYSCALL_INTERRUPTION);
	t->ev->syscall.state = EXITING_SYSCALL;
	t->ev->syscall.no = no;
	t->ev->syscall.desched_rec = rec;
	memcpy(&t->ev->syscall.regs, args, sizeof(t->ev->syscall.regs));
}

void pop_syscall_interruption(Task* t)
{
	pop_event(t, EV_SYSCALL_INTERRUPTION);
}

void log_pending_events(const Task* t)
{
	ssize_t depth = FIXEDSTACK_DEPTH(&t->pending_events);
	int i;

	assert(depth > 0);
	if (1 == depth) {
		log_info("(no pending events)");
		return;
	}

	/* The event at depth 0 is the placeholder event, which isn't
	 * useful to log.  Skip it. */
	for (i = depth - 1; i >= 1; --i) {
		log_event(&t->pending_events.elts[i]);
	}
}

void log_event(const struct event* ev)
{
	const char* name = event_name(ev);
	switch (ev->type) {
	case EV_SENTINEL:
		log_info("%s", name);
		return;
	case EV_DESCHED:
		log_info("%s: %s", name,
			 syscallname(ev->desched.rec->syscallno));
		break;
	case EV_PSEUDOSIG:
		log_info("%s: %d", name, ev->pseudosig.no);
		return;
	case EV_SIGNAL:
	case EV_SIGNAL_DELIVERY:
	case EV_SIGNAL_HANDLER:
		log_info("%s: %s", name, signalname(ev->signal.no));
		return;
	case EV_SYSCALL:
	case EV_SYSCALL_INTERRUPTION:
		log_info("%s: %s", name, syscallname(ev->syscall.no));
		return;
	default:
		fatal("Unknown event type %d", ev->type);
	}
}

const char* event_name(const struct event* ev)
{
	return event_type_name(ev->type);
}
