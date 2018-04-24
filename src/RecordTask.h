/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_RECORD_TASK_H_
#define RR_RECORD_TASK_H_

#include "Registers.h"
#include "Task.h"
#include "TraceFrame.h"

namespace rr {

struct Sighandlers;

/** Different kinds of waits a task can do.
 */
enum WaitType {
  // Not waiting for anything
  WAIT_TYPE_NONE,
  // Waiting for any child process
  WAIT_TYPE_ANY,
  // Waiting for any child with the same process group ID
  WAIT_TYPE_SAME_PGID,
  // Waiting for any child with a specific process group ID
  WAIT_TYPE_PGID,
  // Waiting for a specific process ID
  WAIT_TYPE_PID
};

/** Reasons why we simulate stopping of a task (see ptrace(2) man page).
 */
enum EmulatedStopType {
  NOT_STOPPED,
  GROUP_STOP,          // stopped by a signal. This applies to non-ptracees too.
  SIGNAL_DELIVERY_STOP // Stopped before delivering a signal. ptracees only.
};

/**
 * Pass USE_SYSGOOD to emulate_ptrace_stop to add 0x80 to the signal
 * if PTRACE_O_TRACESYSGOOD is in effect.
 */
enum AddSysgoodFlag { IGNORE_SYSGOOD, USE_SYSGOOD };

struct SyscallbufCodeLayout {
  remote_code_ptr syscallbuf_code_start;
  remote_code_ptr syscallbuf_code_end;
  remote_code_ptr get_pc_thunks_start;
  remote_code_ptr get_pc_thunks_end;
  remote_code_ptr syscallbuf_final_exit_instruction;
};

enum SignalDisposition { SIGNAL_DEFAULT, SIGNAL_IGNORE, SIGNAL_HANDLER };

/**
 * Every Task owned by a RecordSession is a RecordTask. Functionality that
 * only applies during recording belongs here.
 */
class RecordTask : public Task {
public:
  RecordTask(RecordSession& session, pid_t _tid, uint32_t serial,
             SupportedArch a);

  Task* clone(CloneReason reason, int flags, remote_ptr<void> stack,
              remote_ptr<void> tls, remote_ptr<int> cleartid_addr,
              pid_t new_tid, pid_t new_rec_tid, uint32_t new_serial,
              Session* other_session = nullptr) override;
  virtual void post_wait_clone(Task* cloned_from, int flags) override;
  virtual void on_syscall_exit(int syscallno, SupportedArch arch,
                               const Registers& regs) override;
  virtual void will_resume_execution(ResumeRequest, WaitRequest, TicksRequest,
                                     int /*sig*/) override;
  virtual void did_wait() override;
  virtual pid_t own_namespace_tid() override { return own_namespace_rec_tid; }

  std::vector<remote_code_ptr> syscallbuf_syscall_entry_breakpoints();
  bool is_at_syscallbuf_syscall_entry_breakpoint();
  bool is_at_syscallbuf_final_instruction_breakpoint();

  /**
   * Initialize tracee buffers in this, i.e., implement
   * RRCALL_init_syscall_buffer.  This task must be at the point
   * of *exit from* the rrcall.  Registers will be updated with
   * the return value from the rrcall, which is also returned
   * from this call.
   */
  void init_buffers();
  void post_exec();
  /**
   * Called when SYS_rrcall_init_preload has happened.
   */
  virtual void at_preload_init() override;

  RecordSession& session() const;
  TraceWriter& trace_writer() const;

  /**
   * Emulate 'tracer' ptracing this task.
   */
  void set_emulated_ptracer(RecordTask* tracer);
  /**
   * Call this when an event occurs that should stop a ptraced task.
   * If we're emulating ptrace of the task, stop the task and wake the ptracer
   * if it's waiting, and queue "status" to be reported to the
   * ptracer. If siginfo is non-null, we'll report that siginfo, otherwise we'll
   * make one up based on the status (unless the status is an exit code).
   * Returns true if the task is stopped-for-emulated-ptrace, false otherwise.
   */
  bool emulate_ptrace_stop(WaitStatus status,
                           const siginfo_t* siginfo = nullptr, int si_code = 0);
  /**
   * Force the ptrace-stop state no matter what state the task is currently in.
   */
  void force_emulate_ptrace_stop(WaitStatus status);
  /**
   * Called when we're about to deliver a signal to this task. If it's a
   * synthetic SIGCHLD and there's a ptraced task that needs to SIGCHLD,
   * update the siginfo to reflect the status and note that that
   * ptraced task has had its SIGCHLD sent.
   * Note that we can't set the correct siginfo when we send the signal, because
   * it requires us to set information only the kernel has permission to set.
   * Returns false if this signal should be deferred.
   */
  bool set_siginfo_for_synthetic_SIGCHLD(siginfo_t* si);
  /**
   * Sets up |si| as if we're delivering a SIGCHLD/waitid for this waited task.
   */
  template <typename Arch>
  void set_siginfo_for_waited_task(typename Arch::siginfo_t* si) {
    // XXX handle CLD_EXITED here
    if (emulated_stop_type == GROUP_STOP) {
      si->si_code = CLD_STOPPED;
      si->_sifields._sigchld.si_status_ = emulated_stop_code.stop_sig();
    } else {
      si->si_code = CLD_TRAPPED;
      si->_sifields._sigchld.si_status_ = emulated_stop_code.ptrace_signal();
    }
    si->_sifields._sigchld.si_pid_ = tgid();
    si->_sifields._sigchld.si_uid_ = getuid();
  }
  /**
   * Return a reference to the saved siginfo record for the stop-signal
   * that we're currently in a ptrace-stop for.
   */
  siginfo_t& get_saved_ptrace_siginfo();
  /**
   * When emulating a ptrace-continue with a signal number, extract the siginfo
   * that was saved by |save_ptrace_signal_siginfo|. If no such siginfo was
   * saved, make one up.
   */
  siginfo_t take_ptrace_signal_siginfo(int sig);

  /**
   * Returns true if this task is in a waitpid or similar that would return
   * when t's status changes due to a ptrace event.
   */
  bool is_waiting_for_ptrace(RecordTask* t);
  /**
   * Returns true if this task is in a waitpid or similar that would return
   * when t's status changes due to a regular event (exit).
   */
  bool is_waiting_for(RecordTask* t);

  /**
   * Call this to force a group stop for this task with signal 'sig',
   * notifying ptracer if necessary.
   */
  void apply_group_stop(int sig);
  /**
   * Call this after |sig| is delivered to this task.  Emulate
   * sighandler updates induced by the signal delivery.
   */
  void signal_delivered(int sig);
  /**
   * Return true if |sig| is pending but hasn't been reported to ptrace yet
   */
  bool is_signal_pending(int sig);
  /**
   * Return true if there are any signals pending that are not blocked.
   */
  bool has_any_actionable_signal();
  /**
   * Get all threads out of an emulated GROUP_STOP
   */
  void emulate_SIGCONT();
  /**
   * Return true if the disposition of |sig| in |table| isn't
   * SIG_IGN or SIG_DFL, that is, if a user sighandler will be
   * invoked when |sig| is received.
   */
  bool signal_has_user_handler(int sig) const;
  /**
   * If signal_has_user_handler(sig) is true, return the address of the
   * user handler, otherwise return null.
   */
  remote_code_ptr get_signal_user_handler(int sig) const;
  /**
   * Return true if the signal handler for |sig| takes a siginfo_t*
   * parameter.
   */
  bool signal_handler_takes_siginfo(int sig) const;
  /**
   * Return |sig|'s current sigaction. Returned as raw bytes since the
   * data is architecture-dependent.
   */
  const std::vector<uint8_t>& signal_action(int sig) const;
  /** Return true iff |sig| is blocked for this. */
  bool is_sig_blocked(int sig);
  /**
   * Return true iff |sig| is SIG_IGN, or it's SIG_DFL and the
   * default disposition is "ignore".
   */
  bool is_sig_ignored(int sig) const;
  /**
   * Return the applications current disposition of |sig|.
   */
  SignalDisposition sig_disposition(int sig) const;
  /**
   * Return the resolved disposition --- what this signal will actually do,
   * taking into account the default behavior.
   */
  SignalResolvedDisposition sig_resolved_disposition(
      int sig, SignalDeterministic deterministic);
  /**
   * Set the siginfo for the signal-stop of this.
   */
  void set_siginfo(const siginfo_t& si);
  /** Note that the task sigmask needs to be refetched. */
  void invalidate_sigmask() { blocked_sigs_dirty = true; }
  /**
   * Reset the signal handler for this signal to the default.
   */
  void set_sig_handler_default(int sig);

  /**
   * Check that our status for |sig| matches what's in /proc/<pid>/status.
   */
  void verify_signal_states();

  /**
   * Stashed-signal API: if a signal becomes pending at an
   * awkward time, but could be handled "soon", call
   * |stash_sig()| to stash the current pending-signal state.
   *
   * |has_stashed_sig()| obviously returns true if |stash_sig()|
   * has been called successfully.
   *
   * |pop_stash_sig()| restores the (relevant) state of this
   * Task to what was saved in |stash_sig()|, and returns the
   * saved siginfo.  After this call, |has_stashed_sig()| is
   * false.
   *
   * NB: |get_siginfo()| will always return the "real" siginfo,
   * regardless of stash popped-ness state.  Callers must ensure
   * they do the right thing with the popped siginfo.
   *
   * If the process unexpectedly died (due to SIGKILL), we don't
   * stash anything.
   */
  void stash_sig();
  void stash_synthetic_sig(const siginfo_t& si,
                           SignalDeterministic deterministic);
  bool has_stashed_sig() const { return !stashed_signals.empty(); }
  bool has_stashed_sig_not_synthetic_SIGCHLD() const;
  bool has_stashed_sig(int sig) const;
  struct StashedSignal {
    StashedSignal(const siginfo_t& siginfo, SignalDeterministic deterministic)
        : siginfo(siginfo), deterministic(deterministic) {}
    siginfo_t siginfo;
    SignalDeterministic deterministic;
  };
  const StashedSignal* peek_stashed_sig_to_deliver() const;
  void pop_stash_sig(const StashedSignal* stashed);
  void stashed_signal_processed();

  /**
   * Return true if the current state of this looks like the
   * interrupted syscall at the top of our event stack, if there
   * is one.
   */
  bool is_syscall_restart();
  /**
   * Return true iff this is at an execution state where
   * resuming execution may lead to the restart of an
   * interrupted syscall.
   *
   * For example, if a signal without a user handler is about to
   * be delivered to this just after a syscall interruption,
   * then delivering the signal may restart the first syscall
   * and this method will return true.
   */
  bool at_may_restart_syscall() const;
  /**
   * Return true if this is at an arm-desched-event syscall.
   */
  bool is_arm_desched_event_syscall();
  /**
   * Return true if this is at a disarm-desched-event syscall.
   */
  bool is_disarm_desched_event_syscall();
  /**
   * Return true if |t| may not be immediately runnable,
   * i.e., resuming execution and then |waitpid()|'ing may block
   * for an unbounded amount of time.  When the task is in this
   * state, the tracer must await a |waitpid()| notification
   * that the task is no longer possibly-blocked before resuming
   * its execution.
   */
  bool may_be_blocked() const;
  /**
   * Returns true if it looks like this task has been spinning on an atomic
   * access/lock.
   */
  bool maybe_in_spinlock();
  /**
   * Return true if this is within the syscallbuf library.  This
   * *does not* imply that $ip is at a buffered syscall.
   */
  bool is_in_syscallbuf();
  /**
   * Shortcut to the most recent |pending_event->desched.rec| when
   * there's a desched event on the stack, and nullptr otherwise.
   * Exists just so that clients don't need to dig around in the
   * event stack to find this record.
   */
  remote_ptr<const struct syscallbuf_record> desched_rec() const;
  /**
   * Returns true when the task is in a signal handler in an interrupted
   * system call being handled by syscall buffering.
   */
  bool running_inside_desched() const;
  uint16_t get_ptrace_eventmsg_seccomp_data();

  /**
   * Save tracee data to the trace.  |addr| is the address in
   * the address space of this task.  The |record_local*()|
   * variants record data that's already been read from this,
   * and the |record_remote*()| variants read the data and then
   * record it.
   * If 'addr' is null then no record is written.
   */
  void record_local(remote_ptr<void> addr, ssize_t num_bytes, const void* buf);
  template <typename T>
  void record_local(remote_ptr<T> addr, const T* buf, size_t count = 1) {
    record_local(addr, sizeof(T) * count, buf);
  }
  void record_remote(remote_ptr<void> addr, ssize_t num_bytes);
  template <typename T> void record_remote(remote_ptr<T> addr) {
    record_remote(addr, sizeof(T));
  }
  void record_remote(const MemoryRange& range) {
    record_remote(range.start(), range.size());
  }
  // Record as much as we can of the bytes in this range. Will record only
  // contiguous mapped data starting at `addr`.
  void record_remote_fallible(remote_ptr<void> addr, ssize_t num_bytes);
  // Record as much as we can of the bytes in this range. Will record only
  // contiguous mapped-writable data starting at `addr`.
  void record_remote_writeable(remote_ptr<void> addr, ssize_t num_bytes);

  // Simple helper that attempts to use the local mapping to record if one
  // exists
  bool record_remote_by_local_map(remote_ptr<void> addr, size_t num_bytes);

  /**
   * Save tracee data to the trace.  |addr| is the address in
   * the address space of this task.
   * If 'addr' is null then a zero-length record is written.
   */
  void record_remote_even_if_null(remote_ptr<void> addr, ssize_t num_bytes);
  template <typename T> void record_remote_even_if_null(remote_ptr<T> addr) {
    record_remote_even_if_null(addr, sizeof(T));
  }

  /**
   * Manage pending events.  |push_event()| pushes the given
   * event onto the top of the event stack.  The |pop_*()|
   * helpers pop the event at top of the stack, which must be of
   * the specified type.
   */
  void push_event(const Event& ev) { pending_events.push_back(ev); }
  void push_syscall_event(int syscallno);
  void pop_event(EventType expected_type);
  void pop_noop() { pop_event(EV_NOOP); }
  void pop_desched() { pop_event(EV_DESCHED); }
  void pop_seccomp_trap() { pop_event(EV_SECCOMP_TRAP); }
  void pop_signal_delivery() { pop_event(EV_SIGNAL_DELIVERY); }
  void pop_signal_handler() { pop_event(EV_SIGNAL_HANDLER); }
  void pop_syscall() { pop_event(EV_SYSCALL); }
  void pop_syscall_interruption() { pop_event(EV_SYSCALL_INTERRUPTION); }
  virtual void log_pending_events() const override;
  /** Return the event at the top of this's stack. */
  Event& ev() { return pending_events.back(); }
  const Event& ev() const { return pending_events.back(); }

  /**
   * Call this before recording events or data.  Records
   * syscallbuf data and flushes the buffer, if there's buffered
   * data.
   *
   * The timing of calls to this is tricky. We must flush the syscallbuf
   * before recording any data associated with events that happened after the
   * buffered syscalls. But we don't support flushing a syscallbuf twice with
   * no intervening reset, i.e. after flushing we have to be sure we'll get
   * a chance to reset the syscallbuf (i.e. record some other kind of event)
   * before the tracee runs again in a way that might append another buffered
   * syscall --- so we can't flush too early
   */
  void maybe_flush_syscallbuf();
  /**
   * Call this after recording an event when it might be safe to reset the
   * syscallbuf. It must be after recording an event to ensure during replay
   * we run past any syscallbuf after-syscall code that uses the buffer data.
   */
  void maybe_reset_syscallbuf();
  /**
   * Record an event on behalf of this.  Record the registers of
   * this (and other relevant execution state) so that it can be
   * used or verified during replay, if that state is available
   * and meaningful at this's current execution point.
   * |record_current_event()| record |this->ev()|, and
   * |record_event()| records the specified event.
   */
  void record_current_event();
  enum FlushSyscallbuf {
    FLUSH_SYSCALLBUF,
    /* Pass this if it's safe to replay the event before we process the
     * syscallbuf records.
     */
    DONT_FLUSH_SYSCALLBUF
  };
  void record_event(const Event& ev, FlushSyscallbuf flush = FLUSH_SYSCALLBUF,
                    const Registers* registers = nullptr);

  bool is_fatal_signal(int sig, SignalDeterministic deterministic) const;

  /**
   * Return the pid of the newborn thread created by this task.
   * Called when this task has a PTRACE_CLONE_EVENT with CLONE_THREAD.
   */
  pid_t find_newborn_thread();
  /**
   * Return the pid of the newborn process (whose parent has pid `parent_pid`,
   * which need not be the same as the current task's pid, due to CLONE_PARENT)
   * created by this task. Called when this task has a PTRACE_CLONE_EVENT
   * without CLONE_THREAD, or PTRACE_FORK_EVENT.
   */
  pid_t find_newborn_process(pid_t child_parent);

  /**
   * Do a tgkill to send a specific signal to this task.
   */
  void tgkill(int sig);

  /**
   * If the process looks alive, kill it. It is recommended to call try_wait(),
   * on this task before, to make sure liveness is correctly reflected when
   * making this decision
   */
  void kill_if_alive();

  remote_ptr<void> robust_list() const { return robust_futex_list; }
  size_t robust_list_len() const { return robust_futex_list_len; }

  /** Uses /proc so not trivially cheap. */
  pid_t get_parent_pid();

  /**
   * Return true if this is a "clone child" per the wait(2) man page.
   */
  bool is_clone_child() { return termination_signal != SIGCHLD; }

  void set_termination_signal(int sig) { termination_signal = sig; }

  /**
   * When a signal triggers an emulated a ptrace-stop for this task,
   * save the siginfo so a later emulated ptrace-continue with this signal
   * number can use it.
   */
  void save_ptrace_signal_siginfo(const siginfo_t& si);

  enum { SYNTHETIC_TIME_SLICE_SI_CODE = -9999 };

  /**
   * Tasks normally can't change their tid. There is one very special situation
   * where they can: when a non-main-thread does an execve, its tid changes
   * to the tid of the thread-group leader.
   */
  void set_tid_and_update_serial(pid_t tid, pid_t own_namespace_tid);

  /**
   * Return our cached copy of the signal mask, updating it if necessary.
   */
  sig_set_t get_sigmask();
  /**
   * Just get the signal mask of the process.
   */
  sig_set_t read_sigmask_from_process();

  ~RecordTask();

  void maybe_restore_original_syscall_registers();

private:
  /* Retrieve the tid of this task from the tracee and store it */
  void update_own_namespace_tid();

  /**
   * Wait for |futex| in this address space to have the value
   * |val|.
   *
   * WARNING: this implementation semi-busy-waits for the value
   * change.  This must only be used in contexts where the futex
   * will change "soon".
   */
  void futex_wait(remote_ptr<int> futex, int val, bool* ok);

  /**
   * Called when this task is able to receive a SIGCHLD (e.g. because
   * we completed delivery of a signal). Sends a new synthetic
   * SIGCHLD to the task if there are still tasks that need a SIGCHLD
   * sent for them.
   * May queue signals for specific tasks.
   */
  void send_synthetic_SIGCHLD_if_necessary();

  /**
   * Call this when SYS_sigaction is finishing with |regs|.
   */
  void update_sigaction(const Registers& regs);
  /**
   * Update the futex robust list head pointer to |list| (which
   * is of size |len|).
   */
  void set_robust_list(remote_ptr<void> list, size_t len) {
    robust_futex_list = list;
    robust_futex_list_len = len;
  }

  template <typename Arch> void init_buffers_arch();
  template <typename Arch>
  void on_syscall_exit_arch(int syscallno, const Registers& regs);
  /** Helper function for update_sigaction. */
  template <typename Arch> void update_sigaction_arch(const Registers& regs);

  /** Update the clear-tid futex to |tid_addr|. */
  void set_tid_addr(remote_ptr<int> tid_addr);

public:
  Ticks ticks_at_last_recorded_syscall_exit;

  // Scheduler state

  Registers registers_at_start_of_last_timeslice;
  FrameTime time_at_start_of_last_timeslice;
  /* Task 'nice' value set by setpriority(2).
     We use this to drive scheduling decisions. rr's scheduler is
     deliberately simple and unfair; a task never runs as long as there's
     another runnable task with a lower nice value. */
  int priority;
  /* Tasks with in_round_robin_queue set are in the session's
   * in_round_robin_queue instead of its task_priority_set.
   */
  bool in_round_robin_queue;

  // ptrace emulation state

  // Task for which we're emulating ptrace of this task, or null
  RecordTask* emulated_ptracer;
  std::set<RecordTask*> emulated_ptrace_tracees;
  uintptr_t emulated_ptrace_event_msg;
  // Saved emulated-ptrace signals
  std::vector<siginfo_t> saved_ptrace_siginfos;
  // Code to deliver to ptracer/waiter when it waits. Note that zero can be a
  // valid code! Reset to zero when leaving the stop due to PTRACE_CONT etc.
  WaitStatus emulated_stop_code;
  // Always zero while no ptracer is attached.
  int emulated_ptrace_options;
  // One of PTRACE_CONT, PTRACE_SYSCALL --- or 0 if the tracee has not been
  // continued by its ptracer yet, or has no ptracer.
  int emulated_ptrace_cont_command;
  // true when a ptracer/waiter wait() can return |emulated_stop_code|.
  bool emulated_stop_pending;
  // true if this task needs to send a SIGCHLD to its ptracer for its
  // emulated ptrace stop
  bool emulated_ptrace_SIGCHLD_pending;
  // true if this task needs to send a SIGCHLD to its parent for its
  // emulated stop
  bool emulated_SIGCHLD_pending;
  // tracer attached via PTRACE_SEIZE
  bool emulated_ptrace_seized;
  bool emulated_ptrace_queued_exit_stop;
  WaitType in_wait_type;
  pid_t in_wait_pid;

  // Signal handler state

  // Points to the signal-hander table of this task.  If this
  // task is a non-fork clone child, then the table will be
  // shared with all its "thread" siblings.  Any updates made to
  // that shared table are immediately visible to all sibling
  // threads.
  //
  // fork children always get their own copies of the table.
  // And if this task exec()s, the table is copied and stripped
  // of user sighandlers (see below). */
  std::shared_ptr<Sighandlers> sighandlers;
  // If not NOT_STOPPED, then the task is logically stopped and this is the type
  // of stop.
  EmulatedStopType emulated_stop_type;
  // True if the task sigmask may have changed and we need to refetch it.
  bool blocked_sigs_dirty;
  // Most accesses to this should use set_sigmask and get_sigmask to ensure
  // the mirroring to syscallbuf is correct.
  sig_set_t blocked_sigs;
  uint32_t syscallbuf_blocked_sigs_generation;

  // Syscallbuf state

  SyscallbufCodeLayout syscallbuf_code_layout;
  ScopedFd desched_fd;
  /* Value of hdr->num_rec_bytes when the buffer was flushed */
  uint32_t flushed_num_rec_bytes;
  /* Nonzero after the trace recorder has flushed the
   * syscallbuf.  When this happens, the recorder must prepare a
   * "reset" of the buffer, to zero the record count, at the
   * next available slow (taking |desched| into
   * consideration). */
  bool flushed_syscallbuf;
  /* This bit is set when code wants to prevent the syscall
   * record buffer from being reset when it normally would be.
   * This bit is set by the desched code. */
  bool delay_syscallbuf_reset_for_desched;
  /* This is set when code wants to prevent the syscall
   * record buffer from being reset when it normally would be.
   * This is set by the code for handling seccomp SIGSYS signals. */
  bool delay_syscallbuf_reset_for_seccomp_trap;
  // Value to return from PR_GET_SECCOMP
  uint8_t prctl_seccomp_status;

  // Mirrored kernel state
  // This state agrees with kernel-internal values

  // Futex list passed to |set_robust_list()|.  We could keep a
  // strong type for this list head and read it if we wanted to,
  // but for now we only need to remember its address / size at
  // the time of the most recent set_robust_list() call.
  remote_ptr<void> robust_futex_list;
  size_t robust_futex_list_len;
  // The memory cell the kernel will clear and notify on exit,
  // if our clone parent requested it.
  remote_ptr<int> tid_futex;
  /* This is the recorded tid of the tracee *in its own pid namespace*. */
  pid_t own_namespace_rec_tid;
  int exit_code;
  // Signal delivered by the kernel when this task terminates, or zero
  int termination_signal;

  // Our value for PR_GET/SET_TSC (one of PR_TSC_ENABLED, PR_TSC_SIGSEGV).
  int tsc_mode;
  // Our value for ARCH_GET/SET_CPUID (0 -> generate SIGSEGV, 1 -> do CPUID).
  // Only used if session().has_cpuid_faulting().
  int cpuid_mode;
  // The current stack of events being processed.  (We use a
  // deque instead of a stack because we need to iterate the
  // events.)
  std::deque<Event> pending_events;
  // Stashed signal-delivery state, ready to be delivered at
  // next opportunity.
  std::deque<StashedSignal> stashed_signals;
  bool stashed_signals_blocking_more_signals;
  bool break_at_syscallbuf_traced_syscalls;
  bool break_at_syscallbuf_untraced_syscalls;
  bool break_at_syscallbuf_final_instruction;

  // The pmc is programmed to interrupt at a value requested by the tracee, not
  // by rr.
  bool next_pmc_interrupt_is_for_user;

  bool did_record_robust_futex_changes;
};

} // namespace rr

#endif /* RR_RECORD_TASK_H_ */
