/* "Magic" (rr-implemented) syscalls that we use to initialize the
 * syscallbuf.
 *
 * NB: magic syscalls must be positive, because with at least linux
 * 3.8.0 / eglibc 2.17, rr only gets a trap for the *entry* of invalid
 * syscalls, not the exit.  rr can't handle that yet. */
/* TODO: static_assert(LAST_SYSCALL < SYS_rrcall_init_buffers) */

#define RR_CALL_BASE 1000

/**
 * The preload library calls SYS_rrcall_init_preload during its
 * initialization.
 */
#define SYS_rrcall_init_preload RR_CALL_BASE
/**
 * The preload library calls SYS_rrcall_init_buffers in each thread that
 * gets created (including the initial main thread).
 */
#define SYS_rrcall_init_buffers (RR_CALL_BASE + 1)
/**
 * The preload library calls SYS_rrcall_notify_syscall_hook_exit when
 * unlocking the syscallbuf and notify_after_syscall_hook_exit has been set.
 * The word at 4/8(sp) is returned in the syscall result and the word at
 * 8/16(sp) is stored in original_syscallno.
 */
#define SYS_rrcall_notify_syscall_hook_exit (RR_CALL_BASE + 2)
/**
 * When the preload library detects that control data has been received in a
 * syscallbuf'ed recvmsg, it calls this syscall with a pointer to the
 * 'struct msg' returned.
 */
#define SYS_rrcall_notify_control_msg (RR_CALL_BASE + 3)
/**
 * When rr replay has restored the auxv vectors for a new process (completing
 * emulation of exec), it calls this syscall. It takes one parameter, the tid
 * of the task that it has restored auxv vectors for.
 */
#define SYS_rrcall_reload_auxv (RR_CALL_BASE + 4)
/**
 * When rr replay has flushed a syscallbuf 'mprotect' record, notify any outer
 * rr of that flush. The first parameter is the tid of the task, the second
 * parameter is the address, the third parameter is the length, and the
 * fourth parameter is the prot.
 */
#define SYS_rrcall_mprotect_record (RR_CALL_BASE + 5)
/**
 * The audit library calls SYS_rrcall_notify_stap_semaphore_added once a batch
 * of SystemTap semaphores have been incremented. The first parameter is the
 * beginning of an address interval containing semaphores (inclusive) and the
 * second parameter is the end of the address interval (exclusive).
 *
 * In practice a particular probe may be listed in an object's notes more than
 * once, so be prepared to handle overlapping or redundant intervals.
 */
#define SYS_rrcall_notify_stap_semaphore_added (RR_CALL_BASE + 6)
/**
 * The audit library calls SYS_rrcall_notify_stap_semaphore_removed once a
 * batch of previously-incremented SystemTap semaphores have been decremented.
 * The first parameter is the beginning of an address interval containing
 * semaphores (inclusive) and the second parameter is the end of the address
 * interval (exclusive).
 *
 * In practice a particular probe may be listed in an object's notes more than
 * once, so be prepared to handle overlapping or redundant intervals.
 */
#define SYS_rrcall_notify_stap_semaphore_removed (RR_CALL_BASE + 7)
/**
 * This syscall can be used be the application being recorded to check for the
 * presence of the rr recorder. It is used e.g. to enable nested recording of
 * rr itself. Use of this syscall should be limited to situations where it is
 * absolutely necessary to avoid deviation of behavior depending on the
 * presence of absence of rr.
 */
#define SYS_rrcall_check_presence (RR_CALL_BASE + 8)
   /*
    * If `arg1` is `RRCALL_CHECK_SYSCALLBUF_USED_OR_DISABLED`,
    * SYS_rrcall_check_presence returns 0 only if
    * 1) The syscallbuf was used to service the syscall
    * 2) The syscallbuf is disabled
    *
    * Otherwise returns ENOTSUP.
    */
    #define RRCALL_CHECK_SYSCALLBUF_USED_OR_DISABLED 1
/**
 * Requests that rr detach from this process and re-create outside of its
 * process tree, such that it may run without seccomp.
 */
#define SYS_rrcall_detach_teleport (RR_CALL_BASE + 9)
/**
 * Requests that rr reset the time slice signal to the
 * requested period. Used for testing interaction corner
 * cases between the time slice signal and other rr behavior.
 */
#define SYS_rrcall_arm_time_slice (RR_CALL_BASE + 10)
/**
 * Use as
 *
 *  int rr_freeze_tid(pid_t tid, int freeze) {
 *      return syscall(SYS_rrcall_freeze_tid, tid, freeze, 0, 0, 0, 0); }
 *
 * With `freeze=1`, requests that rr's Scheduler not schedule task `tid` again
 * until unfrozen using `rr_freeze_tid(tid, 0)`. Note that kernel scheduling
 * behavior is unaffected. Used for testing Scheduler-sensitive scenarios.
 */
#define SYS_rrcall_freeze_tid (RR_CALL_BASE + 11)
/**
 * Requests a simulated (buffered) RDTSC.
 * The RDTSC value is returned as a 64-bit value stored in the
 * memory location given by the first argument. RAX returns 0.
 */
#define SYS_rrcall_rdtsc (RR_CALL_BASE + 12)
/**
 * For rr's tests: makes rr SIGKILL a task at a particular point in rr's
 * handling of it, as if a SIGKILL that rr doesn't control (from another
 * process, or from a pid namespace being torn down) had arrived right then.
 * This makes races with such SIGKILLs deterministic. Use as
 *
 *   syscall(SYS_rrcall_arm_kill, point, arg, flags, 0, 0, 0)
 *
 * where `point` is one of the RRCALL_KILL_* values below. Each says what
 * `arg` is (it's ignored if the point doesn't use it) and what rr does after
 * sending the SIGKILL, e.g. whether it waits for the task to reach its
 * PTRACE_EVENT_EXIT stop.
 *
 * The kill is armed for the calling thread, replacing whatever was armed
 * for it before. With RRCALL_ARM_KILL_INHERIT in `flags`, each task that the
 * calling thread creates from then on, and each task that those create in
 * turn, gets a copy of the arming; that's how to kill a task before it runs.
 * The copies are independent: rr kills every one of these tasks (and the
 * calling thread) that gets to `point`, and killing one disarms only that
 * one. Likewise, RRCALL_KILL_NONE, or arming another point, changes only
 * what is armed for the calling thread. The arming survives execve, except
 * for the kill points at an execve's PTRACE_EVENT_EXEC stop, which are for
 * the next execve only. rr doesn't kill a task that is already dying (e.g.
 * at its PTRACE_EVENT_EXIT stop).
 *
 * Returns 0, or -EINVAL for an unknown point or flag, or if arguments 4-6
 * aren't 0. The SIGKILL is real, so the trace records it like any other
 * SIGKILL from outside, and replay treats this syscall as a no-op. Without
 * rr, it fails with ENOSYS.
 */
#define SYS_rrcall_arm_kill (RR_CALL_BASE + 13)
#define RRCALL_ARM_KILL_INHERIT 1
enum rrcall_kill_point {
  RRCALL_KILL_NONE,

  /* Before the initial exec */

  /* The initial task, while it's still running rr's own code before its
     first execve (see Task::spawn()): the n'th time rr's recording loop
     takes the task up (RecordSession::record_step()), where `arg` is n,
     before rr does anything there. That's at the task's ptrace stops, and
     between the steps of rr's handling of one (e.g. after rr has recorded a
     syscall's exit, before it resumes the task). rr waits for the task to
     reach its PTRACE_EVENT_EXIT stop, and then handles its exit. A test
     program can arm this, but the arming has no effect, since the program
     only runs after that execve; the undocumented
     `rr record --kill-before-initial-exec=<n>` option arms it in time. */
  RRCALL_KILL_BEFORE_INITIAL_EXEC,

  /* clone(), fork() and vfork() */

  /* A task at its PTRACE_EVENT_CLONE, PTRACE_EVENT_FORK or
     PTRACE_EVENT_VFORK stop, before rr reads the new task's tid. rr doesn't
     wait. */
  RRCALL_KILL_AT_CLONE_EVENT,
  /* A task created by clone(), fork() or vfork(), just before rr maps its
     scratch memory, before the task has run. Arm it with
     RRCALL_ARM_KILL_INHERIT in the task that creates it. rr waits until it
     knows the task is dying (normally the task is then at its
     PTRACE_EVENT_EXIT stop). */
  RRCALL_KILL_BEFORE_CLONE_SCRATCH,
  /* The same, but just after rr's mmap of the scratch memory has taken
     effect. rr then acts as if it had never seen the mmap's result. */
  RRCALL_KILL_AFTER_CLONE_SCRATCH,

  /* execve() */

  /* A thread that execs, at its PTRACE_EVENT_EXEC stop, when rr's scheduler
     collects the stop. Arm it in that thread, right before execve(). rr
     then drops the stop, as if the SIGKILL had arrived before the thread
     got there, and doesn't wait. This and the next three kill points are
     for the thread's next execve only: rr disarms them when the execve
     returns, whether it succeeded or not. */
  RRCALL_KILL_BEFORE_EXEC_STOP,
  /* A thread that execs, at its PTRACE_EVENT_EXEC stop, just before rr
     reads the thread's former tid with PTRACE_GETEVENTMSG, which it does
     when that thread isn't the thread-group leader. Arm it as for
     RRCALL_KILL_BEFORE_EXEC_STOP. rr doesn't wait. */
  RRCALL_KILL_BEFORE_EXEC_GETEVENTMSG,
  /* The same, but rr then waits until the task is at its PTRACE_EVENT_EXIT
     stop (or has exited), without collecting that stop. */
  RRCALL_KILL_BEFORE_EXEC_GETEVENTMSG_AT_EXIT_STOP,
  /* A thread that execs, once rr has handled its PTRACE_EVENT_EXEC stop,
     before the execve returns. Arm it as for RRCALL_KILL_BEFORE_EXEC_STOP.
     rr waits for the task's PTRACE_EVENT_EXIT stop, and doesn't resume it
     from there. */
  RRCALL_KILL_AFTER_EXEC_STOP,
  /* A task whose execve has succeeded, just before rr sets up the new
     address space, at the start of rr's processing of the execve. rr
     doesn't wait for the task to reach its PTRACE_EVENT_EXIT stop, so until
     it does, ptrace requests on it fail with ESRCH. */
  RRCALL_KILL_BEFORE_POST_EXEC,
  /* A task in an execve (entering it, or after it has succeeded), just
     before the n'th syscall that rr makes it do there for its own purposes,
     where `arg` is n. rr waits until it knows the task is dying. */
  RRCALL_KILL_BEFORE_EXEC_REMOTE_SYSCALL,
  /* The same, but just after the n'th syscall. rr then acts as if the task
     had died before reporting the syscall's result. */
  RRCALL_KILL_AFTER_EXEC_REMOTE_SYSCALL,
  /* A task whose execve has succeeded, just before rr maps its scratch
     memory, at the end of rr's processing of the execve. rr waits as for
     RRCALL_KILL_BEFORE_CLONE_SCRATCH. */
  RRCALL_KILL_BEFORE_EXEC_SCRATCH,
  /* A task whose execve has succeeded, after rr has processed the execve,
     just before rr records the syscall exit. rr doesn't wait for the task
     to reach its PTRACE_EVENT_EXIT stop, so until it does, ptrace requests
     on it fail with ESRCH. */
  RRCALL_KILL_BEFORE_EXEC_EXIT_EVENT,

  /* Signals */

  /* A task in a signal-stop for signal `arg`, when rr is waiting for that
     task in particular (not for whichever task stops next), right after
     waitid() has reported the stop, before rr looks at it. rr doesn't wait.
     It first makes the task's threads SCHED_IDLE, so that they're unlikely
     to get to their PTRACE_EVENT_EXIT stops before rr has looked at the
     stop. That relies on rr running on the same CPU as the tracees, as it
     does unless recording with -u. */
  RRCALL_KILL_AFTER_SIGNAL_STOP_WAIT,
  /* A task in a signal-stop for signal `arg`, after rr's waitid() has
     reported the stop but before rr reads the signal's siginfo. rr waits
     until the task has reached its PTRACE_EVENT_EXIT stop (or has exited),
     without collecting that stop. */
  RRCALL_KILL_BEFORE_GETSIGINFO,
  /* A task that blocked in a buffered syscall, when rr handles the syscall
     buffer's desched signal for it by running it on to the syscall buffer's
     next syscall: right after waitid() has reported the first stop there,
     before rr looks at it. (rr doesn't do that if it finds the desched
     signal irrelevant; then it lets the task run normally.) rr doesn't
     wait. It first makes the task's threads SCHED_IDLE, as for
     RRCALL_KILL_AFTER_SIGNAL_STOP_WAIT. */
  RRCALL_KILL_AFTER_DESCHED_STOP_WAIT,

  /* Syscall patching */

  /* A task that has entered syscall number `arg` (of the task's
     architecture) through an instruction that rr is about to patch, just
     before rr takes it out of the syscall to patch it. rr doesn't wait. */
  RRCALL_KILL_BEFORE_SYSCALL_PATCH_EXIT,
  /* The same, but after rr has taken the task out of the syscall, just
     before patching, as if the SIGKILL had arrived during one of the
     syscalls that patching can make the task do. rr waits until it knows
     the task is dying. */
  RRCALL_KILL_BEFORE_SYSCALL_PATCH,

  RRCALL_KILL_NUM_POINTS
};
