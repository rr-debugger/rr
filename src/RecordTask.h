/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_RECORD_TASK_H_
#define RR_RECORD_TASK_H_

#include "Registers.h"
#include "Task.h"
#include "TraceFrame.h"

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

class RecordTask : public Task {
public:
  RecordTask(RecordSession& session, pid_t _tid, pid_t _rec_tid,
             uint32_t serial, SupportedArch a);
  virtual ~RecordTask();

  virtual Task* clone(int flags, remote_ptr<void> stack, remote_ptr<void> tls,
                      remote_ptr<int> cleartid_addr, pid_t new_tid,
                      pid_t new_rec_tid, uint32_t new_serial,
                      Session* other_session);
  virtual void init_buffers(remote_ptr<void> map_hint);
  virtual void on_syscall_exit(int syscallno, const Registers& regs);

  void post_exec();
  /**
   * Called when SYS_rrcall_init_preload has happened.
   */
  virtual void at_preload_init();

  RecordSession& session() const;

  /**
   * Emulate 'tracer' ptracing this task.
   */
  void set_emulated_ptracer(RecordTask* tracer);
  /**
   * Call this when an event occurs that should stop a ptraced task.
   * If we're emulating ptrace of the task, stop the task and wake the ptracer
   * if it's waiting, and queue "code" as an status code to be reported to the
   * ptracer.
   * Returns true if the task is stopped-for-emulated-ptrace, false otherwise.
   */
  bool emulate_ptrace_stop(int code, EmulatedStopType stop_type);
  /**
   * Force the ptrace-stop state no matter what state the task is currently in.
   */
  void force_emulate_ptrace_stop(int code, EmulatedStopType stop_type);
  /**
   * Called when we're about to deliver a signal to this task. If it's a
   * synthetic SIGCHLD and there's a ptraced task that needs to SIGCHLD,
   * update the siginfo to reflect the status and note that that
   * ptraced task has had its SIGCHLD sent.
   */
  void set_siginfo_for_synthetic_SIGCHLD(siginfo_t* si);

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
   * Call this after |sig| is delivered to this task.  Emulate
   * sighandler updates induced by the signal delivery.
   */
  void signal_delivered(int sig);
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
  bool is_sig_blocked(int sig) const;

  /** Set |sig| to be treated as blocked. */
  void set_sig_blocked(int sig);
  /**
   * Return true iff |sig| is SIG_IGN, or it's SIG_DFL and the
   * default disposition is "ignore".
   */
  bool is_sig_ignored(int sig) const;

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
   * Save tracee data to the trace.  |addr| is the address in
   * the address space of this task.  The |record_local*()|
   * variants record data that's already been read from this,
   * and the |record_remote*()| variants read the data and then
   * record it.
   * If 'addr' is null then no record is written.
   */
  void record_local(remote_ptr<void> addr, ssize_t num_bytes, const void* buf);
  template <typename T> void record_local(remote_ptr<T> addr, const T* buf) {
    record_local(addr, sizeof(T), buf);
  }
  void record_remote(remote_ptr<void> addr, ssize_t num_bytes);
  template <typename T> void record_remote(remote_ptr<T> addr) {
    record_remote(addr, sizeof(T));
  }
  // Record as much as we can of the bytes in this range.
  void record_remote_fallible(remote_ptr<void> addr, ssize_t num_bytes);
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
  void record_event(const Event& ev, FlushSyscallbuf flush = FLUSH_SYSCALLBUF);

  /**
   * Return the pid of the newborn thread created by this task.
   * Called when this task has a PTRACE_CLONE_EVENT with CLONE_THREAD.
   */
  pid_t find_newborn_thread();
  /**
   * Return the pid of the newborn process created by this task.
   * Called when this task has a PTRACE_CLONE_EVENT without CLONE_THREAD,
   * or PTRACE_FORK_EVENT.
   */
  pid_t find_newborn_child_process();

  /**
   * Do a tgkill to send a specific signal to this task.
   */
  void tgkill(int sig);

  remote_ptr<void> robust_list() const { return robust_futex_list; }
  size_t robust_list_len() const { return robust_futex_list_len; }

private:
  /**
   * Called when this task is able to receive a SIGCHLD (e.g. because
   * we completed delivery of a signal already). Sends a new synthetic
   * SIGCHLD to the task if there are still ptraced tasks that need a SIGCHLD
   * sent for them.
   */
  void send_synthetic_SIGCHLD_if_necessary();

  /**
   * Call this when SYS_sigaction is finishing with |regs|.
   */
  void update_sigaction(const Registers& regs);
  /**
   * Call this when the tracee is about to complete a
   * SYS_rt_sigprocmask syscall with |regs|.
   */
  void update_sigmask(const Registers& regs);
  /**
   * Update the futex robust list head pointer to |list| (which
   * is of size |len|).
   */
  void set_robust_list(remote_ptr<void> list, size_t len) {
    robust_futex_list = list;
    robust_futex_list_len = len;
  }

  template <typename Arch>
  void on_syscall_exit_arch(int syscallno, const Registers& regs);
  /** Helper function for update_sigaction. */
  template <typename Arch> void update_sigaction_arch(const Registers& regs);

public:
  // Scheduler state

  Registers registers_at_start_of_last_timeslice;
  TraceFrame::Time time_at_start_of_last_timeslice;
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
  // if nonzero, code to deliver to ptracer when it waits
  int emulated_ptrace_stop_code;
  // true if this task needs to send a SIGCHLD to its ptracer for its
  // emulated ptrace stop
  bool emulated_ptrace_SIGCHLD_pending;
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
  // The set of signals that were blocked during a sigsuspend. Only present
  // during the first EV_SIGNAL during an interrupted sigsuspend.
  std::unique_ptr<sig_set_t> sigsuspend_blocked_sigs;
  // If not NOT_STOPPED, then the task is logically stopped and this is the type
  // of stop.
  EmulatedStopType emulated_stop_type;
  sig_set_t blocked_sigs;

  // Syscallbuf state

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
   * Currently, the desched'd syscall code uses this. */
  bool delay_syscallbuf_reset;
  /* True when the tracee has started using the syscallbuf, and
   * the tracer will start receiving PTRACE_SECCOMP events for
   * traced syscalls.  We don't make any attempt to guess at the
   * OS's process/thread semantics; this flag goes on the first
   * time rr sees a PTRACE_SECCOMP event from the task.
   *
   * NB: there must always be at least one traced syscall before
   * any untraced ones; that's the magic "rrcall" the tracee
   * uses to initialize its syscallbuf. */
  bool seccomp_bpf_enabled;
  // Value to return from PR_GET_SECCOMP
  uint8_t prctl_seccomp_status;

  // Futex list passed to |set_robust_list()|.  We could keep a
  // strong type for this list head and read it if we wanted to,
  // but for now we only need to remember its address / size at
  // the time of the most recent set_robust_list() call.
  remote_ptr<void> robust_futex_list;
  size_t robust_futex_list_len;
  /* This is the recorded tid of the tracee *in its own pid namespace*. */
  pid_t own_namespace_rec_tid;
};

#endif /* RR_RECORD_TASK_H_ */
