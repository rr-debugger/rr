/* -*- Mode: C++; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

//#define DEBUGTAG "Recorder"

#include "recorder.h"

#include <assert.h>
#include <linux/futex.h>
#include <linux/net.h>
#include <poll.h>
#include <sched.h>
#include <string.h>
#include <sys/epoll.h>
#include <sysexits.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/wait.h>

#include <sstream>
#include <string>

#include "preload/syscall_buffer.h"

#include "dbg.h"
#include "hpc.h"
#include "record_signal.h"
#include "record_syscall.h"
#include "recorder_sched.h"
#include "task.h"
#include "trace.h"
#include "util.h"

using namespace std;

static string exe_image;
// NB: we currently intentionally leak the constituent strings in
// these arrays.
static CharpVector arg_v;
static CharpVector env_p;

/* Nonzero when it's safe to deliver signals, namely, when the initial
 * tracee has exec()'d the tracee image.  Before then, the address
 * space layout will not be the same during replay as recording, so
 * replay won't be able to find the right execution point to deliver
 * the signal. */
static int can_deliver_signals;

static void copy_argv(int argc, char* argv[])
{
	for (int i = 0; i < argc; ++i) {
		arg_v.push_back(strdup(argv[i]));
	}
	arg_v.push_back(NULL);
}

static void copy_envp(char** envp)
{
	int i = 0, preload_index = -1;
	for (i = 0; envp[i]; ++i) {
		env_p.push_back(strdup(envp[i]));
		if (envp[i] == strstr(envp[i], "LD_PRELOAD=")) {
			preload_index = i;
		}
	}
	// LD_PRELOAD the syscall interception lib
	if (rr_flags()->syscall_buffer_lib_path) {
		string ld_preload = "LD_PRELOAD=";
		// Our preload lib *must* come first
		ld_preload += rr_flags()->syscall_buffer_lib_path;
		if (preload_index >= 0) {
			const char* old_preload =
				strchr(envp[preload_index], '=') + 1;
			assert(old_preload);
			// Honor old preloads too.  this may cause
			// problems, but only in those libs, and
			// that's the user's problem.
			ld_preload += ":";
			ld_preload += old_preload;
		} else {
			/* Or if this is a new key/value, "allocate"
			 * an index for it */
			preload_index = i++;
		}
		env_p.push_back(strdup(ld_preload.c_str()));
	}
	env_p.push_back(NULL);
}

/**
 * Create a pulseaudio client config file with shm disabled.  That may
 * be the cause of a mysterious divergence.  Return an envpair to set
 * in the tracee environment.
 */
static string create_pulseaudio_config()
{
	// TODO let PULSE_CLIENTCONFIG env var take precedence.
	static const char pulseaudio_config_path[] = "/etc/pulse/client.conf";
	if (access(pulseaudio_config_path, R_OK)) {
		fatal("Can't file pulseaudio config at %s.", pulseaudio_config_path);
	}
	char tmp[] = "rr-pulseaudio-client-conf-XXXXXX";
	int fd = mkstemp(tmp);
	unlink(tmp);

	stringstream procfile;
	procfile << "/proc/" << getpid() << "/fd/" << fd;
	stringstream cmd;
	cmd << "cp " << pulseaudio_config_path << " " << procfile.str();
	    
	int status = system(cmd.str().c_str());
	if (-1 == status || !WIFEXITED(status) || 0 != WEXITSTATUS(status)) {
		fatal("The command '%s' failed.", cmd.str().c_str());
	}
	if (-1 == lseek(fd, 0, SEEK_END)) {
		fatal("Failed to seek to end of file.");
	}
	char disable_shm[] = "disable-shm = true\n";
	ssize_t nwritten = write(fd, disable_shm, sizeof(disable_shm) - 1);
	if (nwritten != sizeof(disable_shm) - 1) {
		fatal("Failed to append '%s' to %s",
		      disable_shm, procfile.str().c_str());
	}
	stringstream envpair;
	envpair << "PULSE_CLIENTCONFIG=" << procfile.str();
	return envpair.str();
}

/**
 * Ensure that when we exec the tracee image, the rrpreload lib will
 * be preloaded.  Even if the syscallbuf is disabled, we have to load
 * the preload lib for correctness.
 */
static void ensure_preload_lib_will_load(const char* rr_exe,
					 const CharpVector& envp)
{
	char exe[PATH_MAX];
	strcpy(exe, rr_exe);
	char cmd[] = "check-preload-lib";
	char* argv[] = { exe, cmd, nullptr };
	CharpVector ep = envp;
	char magic_envpair[] = "_RR_CHECK_PRELOAD=1";
	ep[ep.size() - 1] = magic_envpair;
	ep.push_back(nullptr);

	pid_t child = fork();
	if (0 == child) {
		execvpe(rr_exe, argv, ep.data());
		fatal("Failed to exec %s", rr_exe);
	}
	int status;
	pid_t ret = waitpid(child, &status, 0);
	if (ret != child) {
		fatal("Failed to wait for %s child", rr_exe);
	}
	if (!WIFEXITED(status) || 0 != WEXITSTATUS(status)) {
		fprintf(stderr,
"\n"
"rr: error: Unable to preload the '%s' library.\n"
"  Ensure that the library is in your LD_LIBRARY_PATH.  If you installed rr\n"
"  from a distribution package, then the package or your system was not\n"
"  configured correctly.\n"
"\n",
			SYSCALLBUF_LIB_FILENAME);
		exit(EX_CONFIG);
	}
}

static void handle_ptrace_event(Task** tp)
{
	Task* t = *tp;

	/* handle events */
	int event = t->ptrace_event();
	if (event != PTRACE_EVENT_NONE) {
		debug("  %d: handle_ptrace_event %d: event %s",
		      t->tid, event, event_name(t->ev()));
	}
	switch (event) {

	case PTRACE_EVENT_NONE:
	case PTRACE_EVENT_STOP:
		break;

	case PTRACE_EVENT_CLONE:
	case PTRACE_EVENT_FORK: {
		int new_tid = t->get_ptrace_eventmsg();
		void* stack = (void*)t->regs().ecx;
		void* ctid = (void*)t->regs().edi;
		// fork and can never share these resources, only
		// copy, so the flags here aren't meaningful for it.
		int flags_arg = (SYS_clone == t->regs().orig_eax) ?
				t->regs().ebx : 0;
		Task* new_task = t->clone(clone_flags_to_task_flags(flags_arg),
					  stack, ctid, new_tid);
		// Wait until the new task is ready.
		new_task->wait();
		start_hpc(new_task, rr_flags()->max_rbc);
		// Skip past the ptrace event.
		t->cont_syscall();
		assert(t->pending_sig() == 0);
		break;
	}

	case PTRACE_EVENT_EXEC: {
		/* The initial tracee, if it's still around, is now
		 * for sure not running in the initial rr address
		 * space, so we can unblock signals. */
		can_deliver_signals = 1;

		t->push_event(SyscallEvent(SYS_execve));
		t->ev().Syscall().state = ENTERING_SYSCALL;
		record_event(t);
		t->pop_syscall();

		// Skip past the ptrace event.
		t->cont_syscall();
		assert(t->pending_sig() == 0);
		break;
	}

	case PTRACE_EVENT_EXIT: {
		if (EV_SYSCALL == t->ev().type()
		    && SYS_exit_group == t->ev().Syscall().no
		    && t->task_group()->task_set().size() > 1) {
			log_warn("exit_group() with > 1 task; may misrecord CLONE_CHILD_CLEARTID memory race");
			t->destabilize_task_group();
		}

		EventType ev = t->unstable ? EV_UNSTABLE_EXIT : EV_EXIT;
		t->push_event(Event(ev, HAS_EXEC_INFO));
		record_event(t);
		t->pop_event(ev);

		rec_sched_deregister_thread(tp);
		t = *tp;
		break;
	}
	case PTRACE_EVENT_VFORK:
	case PTRACE_EVENT_VFORK_DONE:
	default:
		fatal("Unhandled ptrace event %s(%d)",
		      ptrace_event_name(event), event);
		break;
	}
}

#define debug_exec_state(_msg, _t)					\
	debug(_msg ": status=0x%x pevent=%d",				\
	      (_t)->status(), (_t)->ptrace_event())

enum { DEFAULT_CONT = 0, FORCE_SYSCALL = 1 };
static void task_continue(Task* t, int force_cont, int sig)
{
	bool may_restart = t->at_may_restart_syscall();

	if (sig) {
		debug("  delivering %s to %d", signalname(sig), t->tid);
	}
	if (may_restart && t->seccomp_bpf_enabled) {
		debug("  PTRACE_SYSCALL to possibly-restarted %s",
		      syscallname(t->ev().Syscall().no));
	}

	if (!t->seccomp_bpf_enabled
	    || FORCE_SYSCALL == force_cont || may_restart) {
		/* We won't receive PTRACE_EVENT_SECCOMP events until
		 * the seccomp filter is installed by the
		 * syscall_buffer lib in the child, therefore we must
		 * record in the traditional way (with PTRACE_SYSCALL)
		 * until it is installed. */
		t->cont_syscall_nonblocking(sig);
	} else {
		/* When the seccomp filter is on, instead of capturing
		 * syscalls by using PTRACE_SYSCALL, the filter will
		 * generate the ptrace events. This means we allow the
		 * process to run using PTRACE_CONT, and rely on the
		 * seccomp filter to generate the special
		 * PTRACE_EVENT_SECCOMP event once a syscall happens.
		 * This event is handled here by simply allowing the
		 * process to continue to the actual entry point of
		 * the syscall (using cont_syscall_block()) and then
		 * using the same logic as before. */
		t->cont_nonblocking(sig);
	}
}

/**
 * Resume execution of |t| to the next notable event, such as a
 * syscall.
 */
enum { DONT_NEED_TASK_CONTINUE = 0, NEED_TASK_CONTINUE };
static bool resume_execution(Task* t, int need_task_continue,
			     int force_cont=DEFAULT_CONT)
{
	assert(!t->may_be_blocked());

	debug_exec_state("EXEC_START", t);

	if (need_task_continue) {
		task_continue(t, force_cont, /*no sig*/0);
		if (!t->wait()) {
			debug("  waitpid() interrupted");
			return false;
		}
	}

	if (t->is_ptrace_seccomp_event()) {
		t->seccomp_bpf_enabled = true;
		/* See long comments above. */
		debug("  (skipping past seccomp-bpf trap)");
		return resume_execution(t, NEED_TASK_CONTINUE, FORCE_SYSCALL);
	}
	return true;
}

/**
 * Step |t| forward utnil the desched event is disarmed.  If a signal
 * becomes pending in the interim, the |waitpid()| status is returned,
 * and |si| is filled in.  This allows the caller to deliver the
 * signal after this returns and the desched event is disabled.
 */
static void disarm_desched(Task* t)
{
	int old_sig = 0;

	debug("desched: DISARMING_DESCHED_EVENT");
	/* TODO: send this through main loop. */
	/* TODO: mask off signals and avoid this loop. */
	do {
		t->cont_syscall();
		/* We can safely ignore SIG_TIMESLICE while trying to
		 * reach the disarm-desched ioctl: once we reach it,
		 * the desched'd syscall will be "done" and the tracee
		 * will be at a preemption point.  In fact, we *want*
		 * to ignore this signal.  Syscalls like read() can
		 * have large buffers passed to them, and we have to
		 * copy-out the buffered out data to the user's
		 * buffer.  This happens in the interval where we're
		 * reaching the disarm-desched ioctl, so that code is
		 * susceptible to receiving SIG_TIMESLICE.  If it
		 * does, we'll try to stepi the tracee to a safe point
		 * ... through a practically unbounded memcpy(), which
		 * can be very expensive. */
		int sig = t->pending_sig();
		if (HPC_TIME_SLICE_SIGNAL == sig) {
			continue;
		}
		if (sig && sig == old_sig) {
			debug("  coalescing pending %s", signalname(sig));
			continue;
		}
		if (sig) {
			debug("  %s now pending", signalname(sig));
			t->stash_sig();
		}
	} while (!t->is_disarm_desched_event_syscall());
}

/**
 * |t| is at a desched event and some relevant aspect of its state
 * changed.  (For now, changes except the original desched'd syscall
 * being restarted.)
 */
static void desched_state_changed(Task* t)
{
	switch (t->ev().Desched().state) {
	case IN_SYSCALL:
		debug("desched: IN_SYSCALL");
		/* We need to ensure that the syscallbuf code doesn't
		 * try to commit the current record; we've already
		 * recorded that syscall.  The following event sets
		 * the abort-commit bit. */
		t->push_event(Event(EV_SYSCALLBUF_ABORT_COMMIT, NO_EXEC_INFO));
		t->syscallbuf_hdr->abort_commit = 1;
		record_event(t);
		t->pop_event(EV_SYSCALLBUF_ABORT_COMMIT);

		t->ev().Desched().state = DISARMING_DESCHED_EVENT;
		/* fall through */
	case DISARMING_DESCHED_EVENT: {
		disarm_desched(t);

		t->ev().Desched().state = DISARMED_DESCHED_EVENT;
		record_event(t);
		t->pop_desched();

		/* The tracee has just finished sanity-checking the
		 * aborted record, and won't touch the syscallbuf
		 * during this (aborted) transaction again.  So now is
		 * a good time for us to reset the record counter. */
		t->push_event(Event(EV_SYSCALLBUF_RESET, NO_EXEC_INFO));
		t->syscallbuf_hdr->num_rec_bytes = 0;
		t->delay_syscallbuf_reset = 0;
		t->delay_syscallbuf_flush = 0;
		record_event(t);
		t->pop_event(EV_SYSCALLBUF_RESET);
		// We were just descheduled for potentially a long
		// time, and may have just had a signal become
		// pending.  Ensure we get another chance to run.
		t->switchable = 0;
		return;
	}
	default:
		fatal("Unhandled desched state");
	}
}

static void syscall_not_restarted(Task* t)
{
	debug("  %d: popping abandoned interrupted %s; pending events:",
	      t->tid, syscallname(t->ev().Syscall().no));
#ifdef DEBUGTAG
	log_pending_events(t);
#endif
	t->pop_syscall_interruption();

	t->push_event(Event(EV_INTERRUPTED_SYSCALL_NOT_RESTARTED,
			    NO_EXEC_INFO));
	record_event(t);
	t->pop_event(EV_INTERRUPTED_SYSCALL_NOT_RESTARTED);
}

/**
 * "Thaw" a frozen interrupted syscall if |t| is restarting it.
 * Return nonzero if a syscall is indeed restarted.
 *
 * A postcondition of this function is that |t->ev| is no longer a
 * syscall interruption, whether or whether not a syscall was
 * restarted.
 */
static int maybe_restart_syscall(Task* t)
{
	if (SYS_restart_syscall == t->regs().orig_eax) {
		debug("  %d: SYS_restart_syscall'ing %s",
		      t->tid, syscallname(t->ev().Syscall().no));
	}
	if (t->is_syscall_restart()) {
		t->ev().transform(EV_SYSCALL);
		return 1;
	}
	if (EV_SYSCALL_INTERRUPTION == t->ev().type()) {
		syscall_not_restarted(t);
	}
	return 0;
}

/**
 * After a SYS_sigreturn "exit" of task |t| with return value |ret|,
 * check to see if there's an interrupted syscall that /won't/ be
 * restarted, and if so, pop it off the pending event stack.
 */
static void maybe_discard_syscall_interruption(Task* t, int ret)
{
	int syscallno;

	if (EV_SYSCALL_INTERRUPTION != t->ev().type()) {
		/* We currently don't track syscalls interrupted with
		 * ERESTARTSYS or ERESTARTNOHAND, so it's possible for
		 * a sigreturn not to affect the event stack. */
		debug("  (no interrupted syscall to retire)");
		return;
	}

	syscallno = t->ev().Syscall().no;
	if (0 > ret) {
		syscall_not_restarted(t);
	} else if (0 < ret) {
		assert_exec(t, syscallno == ret,
			    "Interrupted call was %s, and sigreturn claims to be restarting %s",
			    syscallname(syscallno), syscallname(ret));
	}
}

static void syscall_state_changed(Task* t, int by_waitpid)
{
	switch (t->ev().Syscall().state) {
	case ENTERING_SYSCALL: {
		debug_exec_state("EXEC_SYSCALL_ENTRY", t);

		if (!t->ev().Syscall().is_restart) {
			/* Save a copy of the arg registers so that we
			 * can use them to detect later restarted
			 * syscalls, if this syscall ends up being
			 * restarted.  We have to save the registers
			 * in this rather awkward place because we
			 * need the original registers; the restart
			 * (if it's not a SYS_restart_syscall restart)
			 * will use the original registers. */
			t->ev().Syscall().regs = t->regs();
		}

		void* sync_addr = nullptr;
		uint32_t sync_val;
		t->switchable = rec_prepare_syscall(t, &sync_addr, &sync_val);

		// Resume the syscall execution in the kernel context.
		t->cont_syscall_nonblocking();
		debug_exec_state("after cont", t);

		if (sync_addr) {
			t->futex_wait(sync_addr, sync_val);
		}
		t->ev().Syscall().state = PROCESSING_SYSCALL;
		return;
	}
	case PROCESSING_SYSCALL:
		debug_exec_state("EXEC_IN_SYSCALL", t);

		assert(by_waitpid);
		// Linux kicks tasks out of syscalls before delivering
		// signals.
		assert_exec(t, !t->pending_sig(),
			    "Signal %s pending while %d in syscall???",
			    signalname(t->pending_sig()), t->tid);

		t->ev().Syscall().state = EXITING_SYSCALL;
		t->switchable = 0;
		return;

	case EXITING_SYSCALL: {
		int syscallno = t->ev().Syscall().no;
		int may_restart;
		int retval;

		debug_exec_state("EXEC_SYSCALL_DONE", t);

		assert(t->pending_sig() == 0);

		retval = t->regs().eax;

		// sigreturn is a special snowflake, because it
		// doesn't actually return.  Instead, it undoes the
		// setup for signal delivery, which possibly includes
		// preparing the tracee for a restart-syscall.  So we
		// take this opportunity to possibly pop an
		// interrupted-syscall event.
		if (SYS_sigreturn == syscallno
		    || SYS_rt_sigreturn == syscallno) {
			assert(t->regs().orig_eax == -1);
			record_event(t);
			t->pop_syscall();

			// We've finished processing this signal now.
			t->pop_signal_handler();
			t->push_event(Event(EV_EXIT_SIGHANDLER, NO_EXEC_INFO));
			record_event(t);
			t->pop_event(EV_EXIT_SIGHANDLER);

			maybe_discard_syscall_interruption(t, retval);
			// XXX probably not necessary to make the
			// tracee unswitchable
			t->switchable = 0;
			return;
		}

		assert_exec(t, (-ENOSYS != retval
				|| (0 > syscallno
				    || SYS_rrcall_init_buffers == syscallno
				    || SYS_rrcall_monkeypatch_vdso == syscallno
				    || SYS_clone == syscallno
				    || SYS_exit_group == syscallno
				    || SYS_exit == syscallno)),
			    "Exiting syscall %s, but retval is -ENOSYS, usually only seen at entry",
			    syscallname(syscallno));

		debug("  orig_eax:%ld (%s); eax:%ld",
		      t->regs().orig_eax, syscallname(syscallno),
		      t->regs().eax);

		/* a syscall_restart ending is equivalent to the
		 * restarted syscall ending */
		if (t->ev().Syscall().is_restart) {
			debug("  exiting restarted %s", syscallname(syscallno));
		}

		/* TODO: is there any reason a restart_syscall can't
		 * be interrupted by a signal and itself restarted? */
		may_restart = (syscallno != SYS_restart_syscall
			       // SYS_pause is either interrupted or
			       // never returns.  It doesn't restart.
			       && syscallno != SYS_pause
			       && SYSCALL_MAY_RESTART(retval));
		/* no need to process the syscall in case its
		 * restarted this will be done in the exit from the
		 * restart_syscall */
		if (!may_restart) {
			rec_process_syscall(t);
			if (rr_flags()->check_cached_mmaps) {
				t->vm()->verify(t);
			}
		} else {
			debug("  may restart %s (from retval %d)",
			      syscallname(syscallno), retval);

			rec_prepare_restart_syscall(t);
			/* If we may restart this syscall, we've most
			 * likely fudged some of the argument
			 * registers with scratch pointers.  We don't
			 * want to record those fudged registers,
			 * because scratch doesn't exist in replay.
			 * So cover our tracks here. */
			struct user_regs_struct r = t->regs();
			copy_syscall_arg_regs(&r, &t->ev().Syscall().regs);
			t->set_regs(r);
		}
		record_event(t);

		/* If we're not going to restart this syscall, we're
		 * done with it.  But if we are, "freeze" it on the
		 * event stack until the execution point where it
		 * might be restarted. */
		if (!may_restart) {
			t->pop_syscall();
			if (EV_DESCHED == t->ev().type()) {
				debug("  exiting desched critical section");
				desched_state_changed(t);
			}
		} else {
			t->ev().transform(EV_SYSCALL_INTERRUPTION);
			t->ev().Syscall().is_restart = 1;
		}

		t->switchable = 1;
		return;
	}

	default:
		fatal("Unknown exec state %d", t->ev().Syscall().state);
	}
}

/**
 * If the syscallbuf has just been flushed, and resetting hasn't been
 * overridden with a delay request, then record the reset event for
 * replay.
 */
static void maybe_reset_syscallbuf(Task* t)
{
	if (t->flushed_syscallbuf && !t->delay_syscallbuf_reset) {
		t->push_event(Event(EV_SYSCALLBUF_RESET, NO_EXEC_INFO));
		record_event(t);
		t->pop_event(EV_SYSCALLBUF_RESET);
	}
	/* Any code that sets |delay_syscallbuf_reset| is responsible
	 * for recording its own SYSCALLBUF_RESET event at a
	 * convenient time. */
	t->flushed_syscallbuf = 0;
}

/** If the rbc seems to be working return, otherwise don't return. */
static void check_rbc(Task* t)
{
	if (can_deliver_signals || SYS_write != t->ev().Syscall().no) {
		return;
	}
	int fd = t->regs().ebx;
	if (-1 != fd) {
		fprintf(stderr,
"\n"
"rr: error:\n"
"  Unexpected `write(%d, ...)' call from first tracee process.\n"
"  Most likely, the executable image `%s' doesn't exist or isn't\n"
"  in your $PATH.  Terminating recording.\n"
"\n",
			fd, exe_image.c_str());
		terminate_recording(t);
		return;
	}

	int64_t rbc = read_rbc(t->hpc);
	debug("rbc on entry to dummy write: %lld", rbc);
	if (!(rbc > 0)) {
		fprintf(stderr,
"\n"
"rr: internal recorder error:\n"
"  Retired-branch counter doesn't seem to be working.  Are you perhaps\n"
"  running rr in a VM but didn't enable perf-counter virtualization?\n");
		exit(EX_UNAVAILABLE);
	}
}

/**
 * |t| is being delivered a signal, and its state changed.
 * |by_waitpid| is nonzero if the status change was observed by a
 * waitpid() call.
 *
 * Return true if execution was incidentally resumed to a new event,
 * false otherwise.
 */
enum { NOT_BY_WAITPID = 0, BY_WAITPID };
static bool signal_state_changed(Task* t, int by_waitpid)
{
	int sig = t->ev().Signal().no;

	switch (t->ev().type()) {
	case EV_SIGNAL: {
		assert(!by_waitpid);

		// This event is used by the replayer to advance to
		// the point of signal delivery.
		record_event(t);
		reset_hpc(t, rr_flags()->max_rbc);

		t->ev().transform(EV_SIGNAL_DELIVERY);
		ssize_t sigframe_size;
		if (t->signal_has_user_handler(sig)) {
			debug("  %d: %s has user handler", t->tid,
			      signalname(sig));

			if (!t->cont_singlestep(sig)) {
				return false;
			}
			// It's been observed that when tasks enter
			// sighandlers, the singlestep operation above
			// doesn't retire any instructions; and
			// indeed, if an instruction could be retired,
			// this code wouldn't work.  This also
			// cross-checks the sighandler information we
			// maintain in |t->sighandlers|.
#ifdef HPC_ENABLE_EXTRA_PERF_COUNTERS
			assert(0 == read_insts(t->hpc));
#endif
			// It's somewhat difficult engineering-wise to
			// compute the sigframe size at compile time,
			// and it can vary across kernel versions.  So
			// this size is an overestimate of the real
			// size(s).  The estimate was made by
			// comparing $sp before and after entering the
			// sighandler, for a sighandler that used the
			// main task stack.  On linux 3.11.2, that
			// computed size was 1736 bytes, which is an
			// upper bound on the sigframe size.  We don't
			// want to mess with this code much, so we
			// overapproximate the overapproximation and
			// round off to 2048.
			//
			// If this size becomes too small in the
			// future, and unit tests that use sighandlers
			// are run with checksumming enabled, then
			// they can catch errors here.
			sigframe_size = 2048;

			t->ev().transform(EV_SIGNAL_HANDLER);
			t->signal_delivered(sig);
			t->ev().Signal().delivered = 1;
		} else {
			debug("  %d: no user handler for %s", t->tid,
			      signalname(sig));
			sigframe_size = 0;
		}

		// We record this data regardless to simplify replay.
		record_child_data(t, sigframe_size, t->sp());

		// This event is used by the replayer to set up the
		// signal handler frame, or to record the resulting
		// state of the stepi if there wasn't a signal
		// handler.
		record_event(t);

		// If we didn't set up the sighandler frame, we need
		// to ensure that this tracee is scheduled next so
		// that we can deliver the signal normally.  We have
		// to do that because setting up the sighandler frame
		// is synchronous, but delivery otherwise is async.
		// But right after this, we may have to process some
		// syscallbuf state, so we can't let the tracee race
		// with us.
		t->switchable = t->ev().Signal().delivered;
		return false;
	}
	case EV_SIGNAL_DELIVERY:
		if (!t->ev().Signal().delivered) {
			task_continue(t, DEFAULT_CONT, sig);
			if (possibly_destabilizing_signal(t, sig)) {
				log_warn("Delivered core-dumping signal; may misrecord CLONE_CHILD_CLEARTID memory race");
				t->destabilize_task_group();
				t->switchable = 1;
			}
			t->signal_delivered(sig);
			t->ev().Signal().delivered = 1;
			return false;
		}

		// The tracee's waitpid status has changed, so we're finished
		// delivering the signal.
		assert(by_waitpid);
		t->pop_signal_delivery();
		// The event we just |task_continue()|d to above is
		// ready to be prepared.
		return true;

	default:
		fatal("Unhandled signal state %d", t->ev().type());
		return false;	// not reached
	}
}

/**
 * The execution of |t| has just been resumed, and it most likely has
 * a new event that needs to be processed.  Prepare that new event.
 * Pass |si| to force-override signal status.
 */
static void runnable_state_changed(Task* t)
{
	// Have to disable context-switching until we know it's safe
	// to allow switching the context.
	t->switchable = 0;

	siginfo_t* si = nullptr;
	siginfo_t stash;
	if (t->has_stashed_sig()) {
		stash = t->pop_stash_sig();
		si = &stash;
		debug("pulled %s out of stash", signalname(t->pending_sig()));
	}

	if (t->pending_sig() && can_deliver_signals) {
		// This will either push a new signal event, new
		// desched + syscall-interruption events, or no-op.
		handle_signal(t, si);
	} else if (t->pending_sig()) {
		// If the initial tracee isn't prepared to handle
		// signals yet, then us ignoring the ptrace
		// notification here will have the side effect of
		// declining to deliver the signal.
		//
		// This doesn't really occur in practice, only in
		// tests that force a degenerately low time slice.
		log_warn("Dropping %s because it can't be delivered yet",
			 signalname(t->pending_sig()));
		// No events to be recorded, so no syscallbuf updates
		// needed.
		return;
	}

	switch (t->ev().type()) {
	case EV_NOOP:
		t->pop_noop();
		break;
	case EV_SEGV_RDTSC:
	case EV_SCHED:
		record_event(t);
		t->pop_event(t->ev().type());
		t->switchable = 1;
		break;
	case EV_SIGNAL:
		signal_state_changed(t, NOT_BY_WAITPID);
		break;

	case EV_SENTINEL:
	case EV_SIGNAL_HANDLER:
	case EV_SYSCALL_INTERRUPTION:
		// We just entered a syscall.
		if (!maybe_restart_syscall(t)) {
			t->push_event(SyscallEvent(t->regs().orig_eax));
			rec_before_record_syscall_entry(t, t->ev().Syscall().no);
		}
		assert_exec(t, EV_SYSCALL == t->ev().type(),
			    "Should be at syscall event.");
		check_rbc(t);
		t->ev().Syscall().state = ENTERING_SYSCALL;
		record_event(t);
		break;

	default:
		assert_exec(t, false,
			    "%s can't be on event stack at start of new event",
			    t->ev().str().c_str());
		break;
	}
	maybe_reset_syscallbuf(t);
}

static bool term_request;

/**
 * A terminating signal was received.  Set the |term_request| bit to
 * terminate the trace at the next convenient point.
 *
 * If there's already a term request pending, then assume rr is wedged
 * and abort().
 */
static void handle_termsig(int sig)
{
	if (term_request) {
		fatal("Received termsig while an earlier one was pending.  We're probably wedged.");
	}
	log_info("Received termsig %s, requesting shutdown ...\n",
		 signalname(sig));
	term_request = true;
}

static void install_termsig_handlers(void)
{
	int termsigs[] = { SIGINT, SIGTERM };
	for (size_t i = 0; i < ALEN(termsigs); ++i) {
		struct sigaction sa;
		memset(&sa, 0, sizeof(sa));
		sa.sa_handler = handle_termsig;
		sigaction(termsigs[i], &sa, NULL);
	}
}

/** If |term_request| is set, then terminate_recording(). */
static void maybe_process_term_request(Task* t)
{
	if (term_request) {
		terminate_recording(t);
	}
}

void record(const char* rr_exe, int argc, char* argv[], char** envp)
{
	log_info("Start recording...");

	exe_image = argv[0];
	copy_argv(argc, argv);
	copy_envp(envp);
	rec_setup_trace_dir();

	string env_pair = create_pulseaudio_config();
	// Intentionally leaked.
	env_p[env_p.size() - 1] = strdup(env_pair.c_str());
	env_p.push_back(nullptr);

	ensure_preload_lib_will_load(rr_exe, env_p);

	open_trace_files();
	rec_init_trace_files();
	record_argv_envp(argc, arg_v.data(), env_p.data());
	init_libpfm();

	install_termsig_handlers();

	Task* t = Task::create(exe_image, arg_v, env_p);
	start_hpc(t, rr_flags()->max_rbc);

	while (Task::count() > 0) {
		int by_waitpid;

		maybe_process_term_request(t);

		Task* next = rec_sched_get_active_thread(t, &by_waitpid);
		if (!next) {
			maybe_process_term_request(t);
		}
		t = next;

		debug("line %d: Active task is %d. Events:",
		      get_global_time(), t->tid);
#ifdef DEBUGTAG
		log_pending_events(t);
#endif
		int ptrace_event = t->ptrace_event();
		assert_exec(t, (!by_waitpid || t->may_be_blocked() ||
				ptrace_event),
			    "%d unexpectedly runnable (0x%x) by waitpid",
			    t->tid, t->status());
		if (ptrace_event && !t->is_ptrace_seccomp_event()) {
			handle_ptrace_event(&t);
			if (!t) {
				continue;
			}
		}

		bool did_initial_resume = false;
		switch (t->ev().type()) {
		case EV_DESCHED:
			desched_state_changed(t);
			continue;
		case EV_SYSCALL:
			syscall_state_changed(t, by_waitpid);
			continue;
		case EV_SIGNAL_DELIVERY: {
			if ((did_initial_resume =
			     signal_state_changed(t, by_waitpid))) {
				break;
			}
			continue;
		}
		default:
			/* No special handling needed; continue on
			 * below. */
			break;
		}

		if (!t->has_stashed_sig()
		    && !resume_execution(t, (did_initial_resume ?
					  DONT_NEED_TASK_CONTINUE :
					  NEED_TASK_CONTINUE))) {
			maybe_process_term_request(t);
		}
		runnable_state_changed(t);
	}

	log_info("Done recording -- cleaning up");
	close_trace_files();
	close_libpfm();
}

void terminate_recording(Task* t)
{
	log_info("Processing termination request ...");
	log_info("  recording final TRACE_TERMINATION event ...");
	record_trace_termination_event(t);
	flush_trace_files();

	// TODO: Task::killall() here?

	log_info("  exiting, goodbye.");
	exit(0);
}
