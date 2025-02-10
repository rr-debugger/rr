/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_TASK_H_
#define RR_TASK_H_

#include <memory>
#include <vector>
#include <unordered_map>

#include "preload/preload_interface.h"

#include "AddressSpace.h"
#include "Event.h"
#include "ExtraRegisters.h"
#include "FdTable.h"
#include "PerfCounters.h"
#include "Registers.h"
#include "TaskishUid.h"
#include "ThreadGroup.h"
#include "TraceStream.h"
#include "WaitStatus.h"
#include "core.h"
#include "kernel_abi.h"
#include "kernel_supplement.h"
#include "remote_code_ptr.h"
#include "util.h"

struct syscallbuf_hdr;
struct syscallbuf_record;

namespace rr {

class AutoRemoteSyscalls;
class RecordSession;
class ReplaySession;
class ScopedFd;
class Session;
class ThreadGroup;

enum CloneFlags {
  /**
   * The child gets a semantic copy of all parent resources (and
   * becomes a new thread group).  This is the semantics of the
   * fork() syscall.
   */
  CLONE_SHARE_NOTHING = 0,
  /**
   * Child will share the table of signal dispositions with its
   * parent.
   */
  CLONE_SHARE_SIGHANDLERS = 1 << 0,
  /** Child will join its parent's thread group. */
  CLONE_SHARE_THREAD_GROUP = 1 << 1,
  /** Child will share its parent's address space. */
  CLONE_SHARE_VM = 1 << 2,
  /** Child will share its parent's file descriptor table. */
  CLONE_SHARE_FILES = 1 << 3,
  /** Kernel will clear and notify tid futex on task exit. */
  CLONE_CLEARTID = 1 << 4,
  // Set the thread area to what's specified by the |tls| arg.
  CLONE_SET_TLS = 1 << 5,
};

/**
 * Enumeration of ways to resume execution.  See the ptrace manual for
 * details of the semantics of these.
 *
 * We define a new datatype because the PTRACE_SYSEMU* requests aren't
 * part of the official ptrace API, and we want to use a strong type
 * for these resume requests to ensure callers don't confuse their
 * arguments.
 */
enum ResumeRequest {
  RESUME_CONT = PTRACE_CONT,
  RESUME_SINGLESTEP = PTRACE_SINGLESTEP,
  RESUME_SYSCALL = PTRACE_SYSCALL,
  RESUME_SYSEMU = NativeArch::PTRACE_SYSEMU,
  RESUME_SYSEMU_SINGLESTEP = NativeArch::PTRACE_SYSEMU_SINGLESTEP,
};
enum WaitRequest {
  // Don't wait after resuming.
  RESUME_NONBLOCKING,
  // After resuming, blocking-waitpid() until tracee status
  // changes.
  RESUME_WAIT,
  // Like RESUME_WAIT, but we're not expecting a PTRACE_EVENT_EXIT
  // or reap, so return false also in that case.
  RESUME_WAIT_NO_EXIT
};
enum TicksRequest {
  // We don't expect to see any ticks (though we seem to on the odd buggy
  // system...). Using this is a small performance optimization because we don't
  // have to stop and restart the performance counters. This may also avoid
  // bugs on some systems that report performance counter advances while
  // in the kernel...
  RESUME_NO_TICKS = -2,
  RESUME_UNLIMITED_TICKS = -1,
  // Positive values are a request for an interrupt
  // after that number of ticks
  // Don't request more than this!
  MAX_TICKS_REQUEST = 2000000000,
};

/** Reasons why a SIGTRAP might have been delivered. Multiple reasons can
 * apply. Also, none can apply, e.g. if someone sent us a SIGTRAP via kill().
 */
struct TrapReasons {
  /* Singlestep completed (RESUME_SINGLESTEP, RESUME_SYSEMU_SINGLESTEP). */
  bool singlestep;
  /* Hardware watchpoint fired. This includes cases where the actual values
   * did not change (i.e. AddressSpace::has_any_watchpoint_changes may return
   * false even though this is set). */
  bool watchpoint;
  /* Breakpoint instruction was executed. */
  bool breakpoint;
};

struct RseqState {
  remote_ptr<void> ptr;
  uint32_t abort_prefix_signature;
  RseqState(remote_ptr<void> ptr, uint32_t abort_prefix_signature)
    : ptr(ptr), abort_prefix_signature(abort_prefix_signature) {}
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
  friend class Session;
  friend class RecordSession;
  friend class ReplaySession;

public:
  typedef std::vector<WatchConfig> HardwareWatchpoints;

  ReplayTask* as_replay();

  /**
   * Ptrace-detach the task.
   */
  void detach();

  /*
   * Re-enable the CPUID instruction in this task (if it was previously
   * disabled to support CPUID emulation) as well as the use of rdtsc.
   */
  void reenable_cpuid_tsc();

  /**
   * Wait for the task to exit, but do not reap/detach yet.
   */
  void wait_exit();

  /**
   * Advance the task to its exit state if it's not already there.
   * If `wait` is false, then during recording Scheduler::start() must be
   * called.
   */
  void proceed_to_exit(bool wait = true);

  /**
   * Kill this task and wait for it to exit.
   * N.B.: If may_reap() is false, this may hang.
   * Returns the WaitStatus of the task at exit (usually SIGKILL, but may not
   * be if we raced with another exit reason).
   */
  WaitStatus kill();

  /**
   * This must be in an emulated syscall, entered through
   * |cont_sysemu()| or |cont_sysemu_singlestep()|, but that's
   * not checked.  If so, step over the system call instruction
   * to "exit" the emulated syscall.
   */
  void finish_emulated_syscall();

  size_t syscallbuf_data_size();

  /**
   * Dump attributes of this process, including pending events,
   * to |out|, which defaults to LOG_FILE.
   */
  void dump(FILE* out = nullptr) const;

  /**
   * Called after the first exec in a session, when the session first
   * enters a consistent state. Prior to that, the task state
   * can vary based on how rr set up the child process. We have to flush
   * out any state that might have been affected by that.
   */
  void flush_inconsistent_state();

  /**
   * Return total number of ticks ever executed by this task.
   * Updates tick count from the current performance counter values if
   * necessary.
   */
  Ticks tick_count() { return ticks; }

  /**
   * Return the path of this fd as /proc/<pid>/fd/<fd>
   */
  std::string proc_fd_path(int fd);

  /**
   * Return the path of /proc/<pid>/pagemap
   */
  std::string proc_pagemap_path();

  /**
   * Return the path of /proc/<pid>/stat
   */
  std::string proc_stat_path();

  /**
   * Return the path of /proc/<pid>/exe
   */
  std::string proc_exe_path();

  /**
   * Return the path of /proc/<pid>/mem
   */
  std::string proc_mem_path() const;

  /**
   * Return the path of the executable (i.e. what
   * /proc/<pid>/exe points to).
   */
  std::string exe_path();

  /**
   * Stat |fd| in the context of this task's fd table.
   */
  struct stat stat_fd(int fd);
  /**
   * Lstat |fd| in the context of this task's fd table.
   */
  struct stat lstat_fd(int fd);
  /**
   * Open |fd| in the context of this task's fd table.
   */
  ScopedFd open_fd(int fd, int flags);
  /**
   * Get the name of the file referenced by |fd| in the context of this
   * task's fd table.
   */
  std::string file_name_of_fd(int fd);
  /**
   * Get current offset of |fd|
   */
  int64_t fd_offset(int fd);
  /**
   * Get pid of pidfd |fd|
   */
  pid_t pid_of_pidfd(int fd);

  /**
   * Records the wait status of this task as |status|, e.g. if
   * |wait()/try_wait()| has returned it. Call this whenever a waitpid
   * returned activity for this task.
   * If this returns false, the task was kicked out of a ptrace-stop
   * by SIGKILL or equivalent before we could read registers etc:
   * -- We will treat this stop as if it never happened; the caller must
   * act as if there was no stop.
   * -- is_stopped will be false
   * -- in_unexpected_exit will be true
   * If this returns true, is_stopped will be true.
   * If `status.reaped()` (i.e. fatal signal or normal exit), this always
   * returns true.
   */
  bool did_waitpid(WaitStatus status);

  /**
   * Syscalls have side effects on registers (e.g. setting the flags register).
   * Perform those side effects on |registers| to make it look like a syscall
   * happened.
   */
  void canonicalize_regs(SupportedArch syscall_arch);

  /**
   * Return the ptrace message pid associated with the current ptrace
   * event, f.e. the new child's pid at PTRACE_EVENT_CLONE.
   * Returns -1 if the ptrace returns ESRCH, i.e. the task is not in a
   * ptrace-stop.
   */
  pid_t get_ptrace_eventmsg_pid();

  /**
   * Return the siginfo at the signal-stop of this.
   * Not meaningful unless this is actually at a signal stop.
   */
  const siginfo_t& get_siginfo();

  /**
   * Destroy in the tracee task the scratch buffer and syscallbuf (if
   * syscallbuf_child is non-null).
   * Both the as_task and the fd_task must be able to execute remote syscalls
   * and share the address space, resp. the file descriptor table with the
   * current task. If either of these is null, the corresponding resource is
   * not destroyed remote (e.g. if there are no other tasks left in the same
   * address space or file descriptor table).
   */
  void destroy_buffers(Task *as_task, Task *fd_task);
  void destroy_buffers() { destroy_buffers(this, this); }

  void did_kill();

  void unmap_buffers_for(
      AutoRemoteSyscalls& remote, Task* t,
      remote_ptr<struct syscallbuf_hdr> saved_syscallbuf_child);
  /* Close fds related to `t`'s syscallbuf, in this task's fd table.
     If `really_close` is true, actually close the kernel fds through `remote`,
     otherwise only update our FdTable. */
  void close_buffers_for(AutoRemoteSyscalls& remote, Task* t, bool really_close);

  remote_ptr<const struct syscallbuf_record> next_syscallbuf_record();
  long stored_record_size(remote_ptr<const struct syscallbuf_record> record);

  /** Return the current $ip of this. */
  remote_code_ptr ip() { return regs().ip(); }

  /**
   * Emulate a jump to a new IP, updating the ticks counter as appropriate.
   */
  void emulate_jump(remote_code_ptr);
  void count_direct_jump()
  {
    ticks += PerfCounters::ticks_for_unconditional_direct_branch(this);
  }

  /**
   * Return true if this is at an arm-desched-event or
   * disarm-desched-event syscall.
   */
  bool is_desched_event_syscall();

  /**
   * Return true when this task is in a traced syscall made by the
   * syscallbuf code. Callers may assume |is_in_syscallbuf()|
   * is implied by this. Note that once we've entered the traced syscall,
   * ip() is immediately after the syscall instruction.
   */
  bool is_in_traced_syscall() {
    return ip() ==
               as->traced_syscall_ip().increment_by_syscall_insn_length(
                   arch()) ||
           ip() ==
               as->privileged_traced_syscall_ip()
                   .increment_by_syscall_insn_length(arch());
  }
  bool is_at_traced_syscall_entry() {
    return ip() == as->traced_syscall_ip() ||
           ip() == as->privileged_traced_syscall_ip();
  }

  /**
   * Return true when this task is in an untraced syscall, i.e. one
   * initiated by a function in the syscallbuf. Callers may
   * assume |is_in_syscallbuf()| is implied by this. Note that once we've
   * entered the traced syscall, ip() is immediately after the syscall
   * instruction.
   */
  bool is_in_untraced_syscall() {
    const AddressSpace::SyscallType *t;
    if (arch() == aarch64 && stop_sig() > 0) {
      // On aarch64 we can't distinguish untraced syscall entry and exit
      // when a signal happened
      t = AddressSpace::rr_page_syscall_from_entry_point(arch(), ip());
    } else {
      t = AddressSpace::rr_page_syscall_from_exit_point(arch(), ip());
    }
    return t && t->traced == AddressSpace::UNTRACED;
  }

  bool is_in_rr_page() {
    auto p = ip().to_data_ptr<void>();
    return AddressSpace::rr_page_start() <= p &&
           p < AddressSpace::rr_page_end();
  }

  /**
   * Return true if |ptrace_event()| is the trace event
   * generated by the syscallbuf seccomp-bpf when a traced
   * syscall is entered.
   */
  bool is_ptrace_seccomp_event() const;

  /** Dump all pending events to the RecordTask INFO log. */
  virtual void log_pending_events() const {}

  /**
   * Call this hook just before exiting a syscall.  Often Task
   * attributes need to be updated based on the finishing syscall.
   * Use 'regs' instead of this->regs() because some registers may not be
   * set properly in the task yet.
   */
  virtual void on_syscall_exit(int syscallno, SupportedArch arch,
                               const Registers& regs);

  /**
   * Hook called by `resume_execution`.
   */
  virtual void will_resume_execution(ResumeRequest, WaitRequest, TicksRequest,
                                     int /*sig*/) {}
  /**
   * Hook called by `did_waitpid`.
   */
  virtual void did_wait() {}
  /**
   * Return the pid of the task in its own pid namespace.
   * Only RecordTasks actually change pid namespaces, but
   * this value is stored and present during replay too.
   */
  pid_t own_namespace_tid() { return own_namespace_rec_tid; }

  /**
   * Assuming ip() is just past a breakpoint instruction, adjust
   * ip() backwards to point at that breakpoint insn.
   */
  void move_ip_before_breakpoint();

  /**
   * Assuming we've just entered a syscall, exit that syscall and reset
   * state to reenter the syscall just as it was called the first time.
   * Returns false if we see the process exit instead.
   */
  bool exit_syscall_and_prepare_restart();

  /**
   * We're currently in user-space with registers set up to perform a system
   * call. Continue into the kernel and stop where we can modify the syscall
   * state.
   * Return `true` if the syscall entry succeeded.
   * Return `false` if the tracee exited unexpectedly.
   */
  bool enter_syscall(bool allow_exit=false);

  /**
   * We have observed entry to a syscall (either by PTRACE_EVENT_SECCOMP or
   * a syscall, depending on the value of Session::syscall_seccomp_ordering()).
   * Continue into the kernel to perform the syscall and stop at the
   * PTRACE_SYSCALL syscall-exit trap. Returns false if we see the process exit
   * before that; we may or may not be stopped in that case.
   */
  bool exit_syscall();

  /**
   * Return the "task name"; i.e. what |prctl(PR_GET_NAME)| or
   * /proc/tid/comm say that the task's name is.
   *
   * During recording we don't monitor changes to this, we just let
   * the kernel update it directly. This lets us syscall-buffer PR_SET_NAME.
   * During replay we monitor changes to this and cache the name in ReplayTask,
   * hence these methods are virtual. During replay the task's actual name
   * is "rr:" followed by the original name.
   */
  virtual std::string name() const;

  /**
   * Sets the OS-name of this task by injecting system call for PR_SET_NAME.
   * Also updates |prname| to |name|.
   */
  virtual void set_name(AutoRemoteSyscalls& remote, const std::string& name);

  /**
   * Called for every PR_SET_NAME during replay but not always during recording
   * (it is not called for syscall-buffered PR_SET_NAME).
   */
  virtual void did_prctl_set_prname(remote_ptr<void>) {}

  /**
   * Call this method when this task has just performed an |execve()|
   * (so we're in the new address space), but before the system call has
   * returned.
   * `exe_file` is the name of the executable file in the trace, if there is one,
   * otherwise the original exe file name --- a best-effort filename we can
   * pass to gdb for it to read the exe.
   */
  void post_exec(const std::string& exe_file);

  /**
   * Call this method when this task has exited a successful execve() syscall.
   * At this point it is safe to make remote syscalls.
   * `original_exe_file` is the original file exe file name.
   */
  void post_exec_syscall(const std::string& original_exe_file);

  /**
   * Return true if this task has execed.
   */
  bool execed() const;

  /**
   * Return true if this task is dead and just waiting to be reaped.
   */
  virtual bool already_exited() const { return false; }

  virtual bool is_detached_proxy() const { return false; }

  /**
   * Read |N| bytes from |child_addr| into |buf|, or don't
   * return.
   */
  template <size_t N>
  void read_bytes(remote_ptr<void> child_addr, uint8_t (&buf)[N]) {
    return read_bytes_helper(child_addr, N, buf);
  }

  /** Return the current regs of this. */
  const Registers& regs() const;

  /** Return the extra registers of this, or null if the task died. */
  const ExtraRegisters* extra_regs_fallible();

  /** Return the current arch of this. This can change due to exec(). */
  SupportedArch arch() const {
    // Use 'registers' directly instead of calling regs(), since this can
    // be called while the task is not stopped.
    return registers.arch();
  }

  /**
   * Return the debug status (DR6 on x86). The debug status is always cleared
   * in resume_execution() before we resume, so it always only reflects the
   * events since the last resume. Must not be called on non-x86 architectures.
   */
  uintptr_t x86_debug_status();

  /**
   * Set the debug status (DR6 on x86). Noop on non-x86 architectures.
   */
  void set_x86_debug_status(uintptr_t status);

  /**
   * Read the (architecture-specific) pointer authentication keys of the current task
   */
  std::vector<uint8_t> pac_keys(bool *ok = nullptr);

  /**
   * Set the (architecture-specific) pointer authentication keys for the current task
   */
  bool set_pac_keys(const std::vector<uint8_t> &data);

  /**
   * Determine why a SIGTRAP occurred. On x86, uses x86_debug_status() but doesn't
   * consume it.
   */
  TrapReasons compute_trap_reasons();

  /**
   * Called on syscall entry to save any registers that we need to keep, but
   * cannot get from the kernel (r.g. orig_x0 on aarch64).
   */
  void apply_syscall_entry_regs();

  /**
   * Read |val| from |child_addr|.
   * If the data can't all be read, then if |ok| is non-null
   * sets *ok to false, otherwise asserts.
   */
  template <typename T>
  T read_mem(remote_ptr<T> child_addr, bool* ok = nullptr) {
    typename std::remove_cv<T>::type val;
    read_bytes_helper(child_addr, sizeof(val), &val, ok);
    return val;
  }

  /**
   * Read |count| values from |child_addr|.
   */
  template <typename T>
  std::vector<T> read_mem(remote_ptr<T> child_addr, size_t count,
                          bool* ok = nullptr) {
    std::vector<T> v;
    v.resize(count);
    read_bytes_helper(child_addr, sizeof(T) * count, v.data(), ok);
    return v;
  }

  /**
   * Read and return the C string located at |child_addr| in
   * this address space. If the data can't all be read (because the c string to
   * be read is invalid), then if |ok| is non-null, sets *ok to
   * false, otherwise asserts.
   */
  std::string read_c_str(remote_ptr<char> child_addr, bool *ok = nullptr);

  /**
   * Resume execution |how|, delivering |sig| if nonzero.
   * After resuming, |wait_how|. In replay, reset hpcs and
   * request a tick period of tick_period. The default value
   * of tick_period is 0, which means effectively infinite.
   * If interrupt_after_elapsed is nonzero, we interrupt the task
   * after that many seconds have elapsed.
   *
   * All tracee execution goes through here.
   *
   * If `wait_how` == RESUME_WAIT and we don't complete a
   * did_waitpid() (e.g. because the tracee was SIGKILLed or
   * equivalent), this returns false.
   */
  bool resume_execution(ResumeRequest how, WaitRequest wait_how,
                        TicksRequest tick_period, int sig = 0);

  /** Return the session this is part of. */
  Session& session() const { return *session_; }

  /** Set the tracee's registers to |regs|. Lazy. */
  void set_regs(const Registers& regs);

  /** Ensure registers are flushed back to the underlying task.
   *  Returns false if that failed due to the tracee being in
   *  an unexpected state. */
  bool flush_regs();

  /** Set the tracee's extra registers to |regs|. */
  void set_extra_regs(const ExtraRegisters& regs);

  /** Adjust IP for rseq abort if necessary and return true if an abort is required.
   * Sets *rseq_cs_invalid if it was invalid */
  bool should_apply_rseq_abort(EventType event_type, remote_code_ptr* new_ip,
                               bool* invalid_rseq_cs);

  /**
   * Read the aarch64 TLS register via ptrace. Returns true on success, false
   * on failure. On success `result` is set to the tracee's TLS register.
   * This can only fail when ptrace_if_stopped fails, i.e. the tracee
   * is on the exit path due to a SIGKILL or equivalent.
   */
  bool read_aarch64_tls_register(uintptr_t *result);
  void set_aarch64_tls_register(uintptr_t val);

  /**
   * Program the debug registers to the vector of watchpoint
   * configurations in |reg| (also updating the debug control
   * register appropriately).  Return true if all registers were
   * successfully programmed, false otherwise.  Any time false
   * is returned, the caller is guaranteed that no watchpoint
   * has been enabled; either all of |regs| is enabled and true
   * is returned, or none are and false is returned.
   */
  bool set_debug_regs(const HardwareWatchpoints& watchpoints);

  bool set_aarch64_debug_regs(int which, ARM64Arch::user_hwdebug_state *regs, size_t nregs);
  bool get_aarch64_debug_regs(int which, ARM64Arch::user_hwdebug_state *regs);

  uintptr_t get_debug_reg(size_t regno);
  bool set_x86_debug_reg(size_t regno, uintptr_t value);

  /** Update the thread area to |addr|. */
  void set_thread_area(remote_ptr<X86Arch::user_desc> tls);

  /** Set the thread area at index `idx` to desc and reflect this
    * into the OS task. Returns 0 on success, errno otherwise.
    */
  int emulate_set_thread_area(int idx, X86Arch::user_desc desc);

  /** Get the thread area from the remote process.
    * Returns 0 on success, errno otherwise.
    */
  int emulate_get_thread_area(int idx, X86Arch::user_desc& desc);

  const std::vector<X86Arch::user_desc>& thread_areas() {
    DEBUG_ASSERT(arch() == x86 || arch() == x86_64);
    return thread_areas_;
  }

  void set_status(WaitStatus status) { wait_status = status; }

  /**
   * Return true when the task stopped for a ptrace-stop and we
   * haven't resumed it yet.
   */
  bool is_stopped() const { return is_stopped_; }

  /**
   * Setter for `is_stopped_` to update `Scheduler::ntasks_stopped`.
   */
  virtual void set_stopped(bool stopped) { is_stopped_ = stopped; }

  bool in_injectable_signal_stop() const { return in_injectable_signal_stop_; }

  /**
   * Return the status of this as of the last successful wait()/try_wait() call.
   */
  WaitStatus status() const { return wait_status; }

  /**
   * Return the ptrace event as of the last call to |wait()/try_wait()|.
   */
  int ptrace_event() const { return wait_status.ptrace_event(); }

  /**
   * Return the signal that's pending for this as of the last
   * call to |wait()/try_wait()|.  The signal 0 means "no signal".
   */
  int stop_sig() const { return wait_status.stop_sig(); }

  void clear_wait_status() { wait_status = WaitStatus(); }

  /** Return the thread group this belongs to. */
  std::shared_ptr<ThreadGroup> thread_group() const { return tg; }

  /** Return the id of this task's recorded thread group. */
  pid_t tgid() const;
  /** Return id of real OS thread group. */
  pid_t real_tgid() const;

  TaskUid tuid() const { return TaskUid(rec_tid, serial); }

  /** Return the dir of the trace we're using. */
  const std::string& trace_dir() const;

  /**
   * Get the current "time" measured as ticks on recording trace
   * events.  |task_time()| returns that "time" wrt this task
   * only.
   */
  FrameTime trace_time() const;

  /**
   * Call this to reset syscallbuf_hdr->num_rec_bytes and zero out the data
   * recorded in the syscall buffer. This makes for more deterministic behavior
   * especially during replay, where during checkpointing we only save and
   * restore the recorded data area.
   */
  void reset_syscallbuf();

  /**
   * Return the virtual memory mapping (address space) of this
   * task.
   */
  AddressSpace::shr_ptr vm() { return as; }

  FdTable::shr_ptr fd_table() { return fds; }

  /**
   * Block until the status of this changes. wait() expects the wait to end
   * with the process in a stopped() state. If interrupt_after_elapsed >= 0,
   * interrupt the task after that many seconds have elapsed. If
   * interrupt_after_elapsed == 0.0, the interrupt will happen immediately.
   * Returns false if the wait failed because we reached a stop but we got
   * SIGKILLed (or equivalent) out of it, in which case it is not safe to wait
   * because that might block indefinitely waiting for us to acknowledge the
   * PTRACE_EVENT_EXIT of other tasks. In this case in_unexpected_exit will
   * be true and is_stopped will be false.
   * This can't reap the task.
   */
  bool wait(double interrupt_after_elapsed = -1);

  /**
   * Currently we don't allow recording across uid changes, so we can
   * just return rr's uid.
   */
  uid_t getuid() { return ::getuid(); }

  /**
   * Write |N| bytes from |buf| to |child_addr|, or don't return.
   */
  template <size_t N>
  void write_bytes(remote_ptr<void> child_addr, const uint8_t (&buf)[N]) {
    write_bytes_helper(child_addr, N, buf);
  }

  enum WriteFlags {
    IS_BREAKPOINT_RELATED = 0x1,
  };
  /**
   * Write |val| to |child_addr|.
   */
  template <typename T>
  void write_mem(remote_ptr<T> child_addr, const T& val, bool* ok = nullptr,
                 uint32_t flags = 0) {
    DEBUG_ASSERT(type_has_no_holes<T>());
    write_bytes_helper(child_addr, sizeof(val), static_cast<const void*>(&val),
                       ok, flags);
  }
  /**
   * This is not the helper you're looking for.  See above: you
   * probably accidentally wrote |write_mem(addr, &foo)| when
   * you meant |write_mem(addr, foo)|.
   */
  template <typename T>
  void write_mem(remote_ptr<T> child_addr, const T* val) = delete;

  template <typename T>
  void write_mem(remote_ptr<T> child_addr, const T* val, int count,
                 bool* ok = nullptr) {
    DEBUG_ASSERT(type_has_no_holes<T>());
    write_bytes_helper(child_addr, sizeof(*val) * count,
                       static_cast<const void*>(val), ok);
  }

  uint64_t write_ranges(const std::vector<FileMonitor::Range>& ranges,
                        void* data, size_t size);

  /**
   * Writes zeroes to the given memory range.
   * For efficiency tries using MADV_REMOVE via `remote`. Caches
   * an AutoRemoteSyscalls in `*remote`.
   */
  void write_zeroes(std::unique_ptr<AutoRemoteSyscalls>* remote, remote_ptr<void> addr, size_t size);

  /**
   * Don't use these helpers directly; use the safer and more
   * convenient variants above.
   *
   * Read/write the number of bytes that the template wrapper
   * inferred.
   */
  ssize_t read_bytes_fallible(remote_ptr<void> addr, ssize_t buf_size,
                              void* buf);
  /**
   * If the data can't all be read, then if |ok| is non-null, sets *ok to
   * false, otherwise asserts.
   */
  void read_bytes_helper(remote_ptr<void> addr, ssize_t buf_size, void* buf,
                         bool* ok = nullptr);
  /**
   * |flags| is bits from WriteFlags.
   */
  ssize_t write_bytes_helper(remote_ptr<void> addr, ssize_t buf_size,
                          const void* buf, bool* ok = nullptr,
                          uint32_t flags = 0);
  /**
   * |flags| is bits from WriteFlags.
   * Returns number of bytes written.
   */
  ssize_t write_bytes_helper_no_notifications(remote_ptr<void> addr, ssize_t buf_size,
                                              const void* buf, bool* ok = nullptr,
                                              uint32_t flags = 0);

  /**
   * This task has been selected to run next.
   */
  void will_schedule();

  SupportedArch detect_syscall_arch();

  /**
   * Call this when performing a clone syscall in this task. Returns
   * true if the call completed, false if it was interrupted and
   * needs to be resumed. When the call returns true, the task is
   * stopped at a PTRACE_EVENT_CLONE or PTRACE_EVENT_FORK.
   */
  bool clone_syscall_is_complete(pid_t* new_pid, SupportedArch syscall_arch);

  /**
   * Called when SYS_rrcall_init_preload has happened.
   */
  virtual void at_preload_init();

  /**
   * Open /proc/[tid]/mem fd for our AddressSpace, closing the old one
   * first. If necessary we force the tracee to open the file
   * itself and smuggle the fd back to us.
   * Returns false if the process no longer exists.
   */
  bool open_mem_fd();

  /**
   * Calls open_mem_fd if this task's AddressSpace doesn't already have one.
   */
  void open_mem_fd_if_needed();

  /**
   * Open /proc/[tid]/pagemap fd for our AddressSpace.
   */
  ScopedFd& pagemap_fd();

  /**
   * Perform a PTRACE_INTERRUPT and set up the counter for potential spurious stops
   * to be detected in `account_for_potential_ptrace_interrupt_stop`.
   * Returns true if it succeeded, false if we got ESRCH (i.e. the tracee has
   * disappeared or is not being ptraced; PTRACE_INTERRUPT doesn't require the
   * tracee to be stopped).
   */
  bool do_ptrace_interrupt();

  /**
   * Sometimes we use PTRACE_INTERRUPT to kick the tracee out of various
   * undesirable states. Unfortunately, that can (but need not) result in later
   * undesired GROUP-STOP-SIGTRAP stops which report the PTRACE_INTERRUPT.
   * This function may be called when examining stops to account for any
   * such spurious stops.
   *
   * Should be called at exactly once for every ptrace stop.
   *
   * Returns true if the stop is caused by a PTRACE_INTERRUPT we know about,
   * false otherwise.
   */
  bool account_for_potential_ptrace_interrupt_stop(WaitStatus status);

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
  remote_ptr<void> scratch_ptr;
  /* The full size of the scratch buffer.
   * The last page of the scratch buffer is used as an alternate stack
   * for the syscallbuf code. So the usable size is less than this.
   */
  ssize_t scratch_size;

  /* The child's desched counter event fd number */
  int desched_fd_child;
  /* The child's cloned_file_data_fd */
  int cloned_file_data_fd_child;
  /* The filename opened by the child's cloned_file_data_fd */
  std::string cloned_file_data_fname;
  // Current rseq state if registered
  std::unique_ptr<RseqState> rseq_state;

  PerfCounters hpc;

  /* This is always the "real" tid of the tracee. For a detached proxy,
   * it's the proxy tid. */
  pid_t tid;
  /* This is always the recorded tid of the tracee.  During
   * recording, it's synonymous with |tid|, and during replay
   * it's the tid that was recorded. For a detached proxy,
   * this is the tid of the detachd process. */
  pid_t rec_tid;
  /* This is the recorded tid of the tracee *in its own pid namespace*. */
  pid_t own_namespace_rec_tid;

  size_t syscallbuf_size;
  /* Points at the tracee's mapping of the buffer. */
  remote_ptr<struct syscallbuf_hdr> syscallbuf_child;

  remote_ptr<struct preload_globals> preload_globals;
  typedef uint8_t ThreadLocals[PRELOAD_THREAD_LOCALS_SIZE];
  ThreadLocals thread_locals;

  size_t usable_scratch_size() {
    return std::max<ssize_t>(0, scratch_size - page_size());
  }
  remote_ptr<void> syscallbuf_alt_stack() {
    return scratch_ptr.is_null() ? remote_ptr<void>()
                                 : scratch_ptr + scratch_size;
  }
  void setup_preload_thread_locals();
  void setup_preload_thread_locals_from_clone(Task* origin);
  // If `fetch_full` is false, avoid fetching the full stub_scratch_2 on aarch64
  // and only fetch the first two pointers from it.
  const ThreadLocals& fetch_preload_thread_locals();
  void activate_preload_thread_locals();

  struct CapturedState {
    Ticks ticks;
    Registers regs;
    ExtraRegisters extra_regs;
    std::string prname;
    uintptr_t fdtable_identity;
    remote_ptr<struct syscallbuf_hdr> syscallbuf_child;
    size_t syscallbuf_size;
    size_t num_syscallbuf_bytes;
    remote_ptr<struct preload_globals> preload_globals;
    remote_ptr<void> scratch_ptr;
    ssize_t scratch_size;
    remote_ptr<void> top_of_stack;
    std::unique_ptr<RseqState> rseq_state;
    uint64_t cloned_file_data_offset;
    ThreadLocals thread_locals;
    pid_t rec_tid;
    pid_t own_namespace_rec_tid;
    uint32_t serial;
    ThreadGroupUid tguid;
    int desched_fd_child;
    int cloned_file_data_fd_child;
    std::string cloned_file_data_fname;
    WaitStatus wait_status;
    // TLS state (architecture specific)
    // On x86_64 the tls register is part of the general register state (%fs)
    // On x86 thread_areas is used
    // on aarch64, tls_register is used
    uintptr_t tls_register;
    std::vector<X86Arch::user_desc> thread_areas;
  };

  /**
   * Lock or unlock the syscallbuf to prevent the preload library from using it.
   * Only has an effect if the syscallbuf has been initialized.
   */
  void set_syscallbuf_locked(bool locked);

  // Disable syscall buffering during diversions
  void set_in_diversion(bool in_diversion) {
    if (preload_globals) {
      write_mem(REMOTE_PTR_FIELD(preload_globals, in_diversion),
                (unsigned char)in_diversion);
    }
    set_syscallbuf_locked(in_diversion);
  }

  /**
   * Executes a ptrace() call that expects the task to be in a ptrace-stop.
   * Errors other than ESRCH are treated as fatal (those are rr bugs).
   * Only call this when `Task::is_stopped_`.
   * Even when `is_stopped_` is true, this can return false because the kernel
   * could have pushed the task out of the ptrace-stop due to SIGKILL or
   * equivalent (such as `zap_pid_ns_processes`).
   *
   * So when this returns false, one of the following is true:
   * * The tracee is executing towards its PTRACE_EVENT_EXIT stop. This
   * happens concurrently with rr so it may enter that stop at any time.
   * But it can also be indefinitely delayed before reaching the exit stop,
   * e.g. waiting in`zap_pid_ns_processes`.
   * * In older kernels (before 9a95f78eab70deeb5a4c879c19b841a6af5b66e7)
   * it is possible for a tracee stopped in PTRACE_EVENT_EXIT to be kicked
   * out of that stop by another SIGKILL. In that case it is executing towards
   * or has actually reached the zombie state. In old kernels it can be
   * blocked indefinitely from reaching the zombie state due to coredumping.
   *
   * In either of these cases, the tracee has been killed via SIGKILL or equivalent
   * and will not execute user code or system calls again. We can assume
   * its registers won't change again. It won't handle any more signals.
   */
  bool ptrace_if_stopped(int request, remote_ptr<void> addr, void* data);

  /**
   * Make the ptrace |request| with |addr| and |data|, return
   * the ptrace return value. Just a very thin wrapper around the syscall.
   */
  long fallible_ptrace(int request, remote_ptr<void> addr, void* data);

  bool is_exiting() const {
    return seen_ptrace_exit_event_ || was_reaped_ || in_unexpected_exit;
  }

  bool seen_ptrace_exit_event() const {
    return seen_ptrace_exit_event_;
  }

  void did_handle_ptrace_exit_event();

  remote_code_ptr last_execution_resume() const {
    return address_of_last_execution_resume;
  }

  bool was_reaped() const {
    return was_reaped_;
  }
  bool handled_ptrace_exit_event() const {
    return handled_ptrace_exit_event_;
  }
  bool stopped_or_unexpected_exit() const {
    return is_stopped_ || was_reaped_ || in_unexpected_exit;
  }

  void os_exec(SupportedArch arch, std::string filename);
  void os_exec_stub(SupportedArch arch) {
      os_exec(arch, find_exec_stub(arch));
  }

  /**
   * Try to make the current task look exactly like some `other` task
   * by copying that task's address space and other relevant properties,
   * but without using the os's clone system call.
   */
  void dup_from(Task *task);

  virtual ~Task();

  /**
   * Fork and exec the initial task. If something goes wrong later
   * (i.e. an exec does not occur before an exit), an error may be
   * readable from the other end of the pipe whose write end is error_fd.
   */
  static Task* spawn(Session& session, ScopedFd& error_fd,
                     ScopedFd* sock_fd_out,
                     ScopedFd* sock_fd_receiver_out,
                     int* tracee_socket_fd_number_out,
                     const std::string& exe_path,
                     const std::vector<std::string>& argv,
                     const std::vector<std::string>& envp, pid_t rec_tid = -1);

  /**
   * Do PTRACE_SEIZE on this tid with the correct ptrace options.
   */
  static long ptrace_seize(pid_t tid, Session& session);

  /**
   * Do a tgkill to send a specific signal to this task.
   */
  void tgkill(int sig);

  /**
   * Try to move this task to a signal stop by signaling it with the
   * syscallbuf desched signal (which is guaranteed not to be blocked).
   * Returns false if the task exited unexpectedly.
   */
  bool move_to_signal_stop();

  // A map from original table to (potentially detached) clone, to preserve
  // FdTable sharing relationships during a session fork.
  using ClonedFdTables = std::unordered_map<uintptr_t, FdTable::shr_ptr>;

  /**
   * Just forget that this Task exists. Another rr process will manage it.
   */
  void forget();

  // Used on aarch64 to detect whether we've recorded x0 and x8 on syscall entry
  Ticks ticks_at_last_syscall_entry;
  remote_code_ptr ip_at_last_syscall_entry;
  // Whether the syscall entry corresponding to `{ticks,ip}_at_last_syscall_entry`
  // has been recorded in the trace
  // (used to avoid double recording on unexpected exit)
  bool last_syscall_entry_recorded;

  /*
   * Called before the scheduler resumes a task to check if the task's address
   * space has any leftover syscallbufs from dead processes which shared the
   * address space
   */
  void unmap_dead_syscallbufs_if_required();

protected:
  Task(Session& session, pid_t tid, pid_t rec_tid, uint32_t serial,
       SupportedArch a);

  enum CloneReason {
    // Cloning a task in the same session due to tracee fork()/vfork()/clone()
    TRACEE_CLONE,
    // Cloning a task into a new session as the leader for a checkpoint
    SESSION_CLONE_LEADER,
    // Cloning a task into the same session to recreate threads while
    // restoring a checkpoint
    SESSION_CLONE_NONLEADER,
  };
  /**
   * Return a new Task cloned from |p|.  |flags| are a set of
   * CloneFlags (see above) that determine which resources are
   * shared or copied to the new child.  |new_tid| is the tid
   * assigned to the new task by the kernel.  |new_rec_tid| is
   * only relevant to replay, and is the pid that was assigned
   * to the task during recording.
   */
  virtual Task* clone(CloneReason reason, int flags, remote_ptr<void> stack,
                      remote_ptr<void> tls, remote_ptr<int> cleartid_addr,
                      pid_t new_tid, pid_t new_rec_tid, uint32_t new_serial,
                      Session* other_session = nullptr,
                      FdTable::shr_ptr new_fds = nullptr,
                      ThreadGroup::shr_ptr new_tg = nullptr);

  /**
   * Internal method called after the first wait() during a clone().
   */
  virtual void post_wait_clone(Task*, int) {}

  /**
   * Internal method called after the clone to fix up the new address space.
   */
  virtual bool post_vm_clone(CloneReason reason, int flags, Task* origin);

  template <typename Arch>
  void on_syscall_exit_arch(int syscallno, const Registers& regs);

  /** Helper function for init_buffers. */
  template <typename Arch> void init_buffers_arch(remote_ptr<void> map_hint);

  /**
   * Grab state from this task into a structure that we can use to
   * initialize a new task via os_clone_into/os_fork_into and copy_state.
   */
  CapturedState capture_state();

  /**
   * Make this task look like an identical copy of the task whose state
   * was captured by capture_task_state(), in
   * every way relevant to replay.  This task should have been
   * created by calling os_clone_into() or os_fork_into(),
   * and if it wasn't results are undefined.
   *
   * Some task state must be copied into this by injecting and
   * running syscalls in this task.  Other state is metadata
   * that can simply be copied over in local memory.
   */
  void copy_state(const CapturedState& state);

  /**
   * Read tracee memory using PTRACE_PEEKDATA calls. Slow, only use
   * as fallback. Returns number of bytes actually read.
   */
  ssize_t read_bytes_ptrace(remote_ptr<void> addr, ssize_t buf_size, void* buf);

  /**
   * Write tracee memory using PTRACE_POKEDATA calls. Slow, only use
   * as fallback. Returns number of bytes actually written.
   */
  ssize_t write_bytes_ptrace(remote_ptr<void> addr, ssize_t buf_size,
                             const void* buf);

  /**
   * Try writing 'buf' to 'addr' by replacing pages in the tracee
   * address-space using a temporary file. This may work around PaX issues.
   */
  bool try_replace_pages(remote_ptr<void> addr, ssize_t buf_size,
                         const void* buf);

  /**
   * Map the syscallbuffer for this, shared with this process.
   * |map_hint| is the address where the syscallbuf is expected
   * to be mapped --- and this is asserted --- or nullptr if
   * there are no expectations.
   * Initializes syscallbuf_child.
   */
  KernelMapping init_syscall_buffer(AutoRemoteSyscalls& remote,
                                    remote_ptr<void> map_hint);

  /**
   * Make the OS-level calls to create a new fork or clone that
   * will eventually be a copy of this task and return that Task
   * metadata.  These methods are used in concert with
   * |Task::copy_state()| to create task copies during
   * checkpointing.
   *
   * For |os_fork_into()|, |session| will be tracking the
   * returned fork child.
   *
   * For |os_clone_into()|, |task_leader| is the "main thread"
   * in the process into which the copy of this task will be
   * created.  |task_leader| will perform the actual OS calls to
   * create the new child.
   */
  Task* os_fork_into(Session* session, FdTable::shr_ptr new_fds);
  static Task* os_clone_into(const CapturedState& state,
                             AutoRemoteSyscalls& remote,
                             const ClonedFdTables& cloned_fd_tables,
                             ThreadGroup::shr_ptr new_tg);

  /**
   * Return the TraceStream that we're using, if in recording or replay.
   * Returns null if we're not in record or replay.
   */
  const TraceStream* trace_stream() const;

  /**
   * Make the OS-level calls to clone |parent| into |session|
   * and return the resulting Task metadata for that new
   * process.  This is as opposed to |Task::clone()|, which only
   * attaches Task metadata to an /existing/ process.
   *
   * The new clone will be tracked in |session|.  The other
   * arguments are as for |Task::clone()| above.
   */
  static Task* os_clone(CloneReason reason, Session* session,
                        AutoRemoteSyscalls& remote, pid_t rec_child_tid,
                        uint32_t new_serial, unsigned base_flags,
                        FdTable::shr_ptr new_fds = nullptr,
                        ThreadGroup::shr_ptr new_tg = nullptr,
                        remote_ptr<void> stack = nullptr,
                        remote_ptr<int> ptid = nullptr,
                        remote_ptr<void> tls = nullptr,
                        remote_ptr<int> ctid = nullptr);

  void work_around_KNL_string_singlestep_bug();

  void* preload_thread_locals();

  uint32_t serial;
  // The address space of this task.
  AddressSpace::shr_ptr as;
  // The file descriptor table of this task.
  FdTable::shr_ptr fds;
  // Count of all ticks seen by this task since tracees became
  // consistent and the task last wait()ed.
  Ticks ticks;
  // Copy of the child registers.
  // When is_stopped_ or in_unexpected_exit, these are the source of
  // truth. Otherwise the child is running and the registers could be
  // changed by the kernel or user-space execution, and the values here
  // are meaningless.
  // See also registers_dirty.
  Registers registers;
  // Where we last resumed execution
  remote_code_ptr address_of_last_execution_resume;
  // Current hardware watchpoint state as programmed into debug registers
  HardwareWatchpoints current_hardware_watchpoints;
  ResumeRequest how_last_execution_resumed;
  // In certain circumstances, due to hardware bugs, we need to fudge the
  // cx register. If so, we record the original value here. See comments in
  // Task.cc
  uint64_t last_resume_orig_cx;
  // The instruction type we're singlestepping through.
  SpecialInst singlestepping_instruction;
  // True if we set a breakpoint after a singlestepped CPUID instruction.
  // We need this in addition to `singlestepping_instruction` because that
  // might be CPUID but we failed to set the breakpoint.
  bool did_set_breakpoint_after_cpuid;
  // True when we know via waitpid() that the task was stopped in
  // a ptrace-stop and we haven't resumed it.
  // It is possible that the task has been pushed out of the ptrace-stop
  // without our knowledge, due to a SIGKILL or equivalent such as
  // zap_pid_ns_processes.
  bool is_stopped_;
  // True when we've been kicked out of a ptrace-stop via SIGKILL or
  // equivalent.
  bool in_unexpected_exit;
  // True when the task is stopped in a signal-stop where we can
  // inject our own signal. Usually equal to wait_status.stop_sig() > 0,
  // but can be different if an AutoRemoteSyscalls changed our state and
  // then restored wait_status.
  bool in_injectable_signal_stop_;
  /* True when the seccomp filter has been enabled via prctl(). This happens
   * in the first system call issued by the initial tracee (after it returns
   * from kill(SIGSTOP) to synchronize with the tracer). */
  bool seccomp_bpf_enabled;
  // True when 'registers' has changes that haven't been flushed back to the
  // task yet.
  bool registers_dirty;
  // True when changes to the original syscallno in 'registers' have not been
  // flushed back to the task yet. Some architectures (e.g. AArch64) require a
  // separate ptrace call for this.
  bool orig_syscallno_dirty;
  // When |extra_registers_known|, we have saved our extra registers.
  ExtraRegisters extra_registers;
  bool extra_registers_known;
  // The session we're part of.
  Session* session_;
  // The thread group this belongs to.
  std::shared_ptr<ThreadGroup> tg;
  // Entries set by |set_thread_area()| or the |tls| argument to |clone()|
  // (when that's a user_desc). May be more than one due to different
  // entry_numbers.
  // x86(_64) only.
  std::vector<X86Arch::user_desc> thread_areas_;
  // The |stack| argument passed to |clone()|, which for
  // "threads" is the top of the user-allocated stack.
  remote_ptr<void> top_of_stack;
  // The most recent status of this task as returned by
  // waitpid().
  WaitStatus wait_status;
  // The most recent siginfo (captured when wait_status shows pending_sig())
  siginfo_t pending_siginfo;
  // True when a PTRACE_EXIT_EVENT has been observed in the wait_status
  // for this task.
  bool seen_ptrace_exit_event_;
  // True when a PTRACE_EXIT_EVENT has been handled for this task.
  // By handled we mean either RecordSession's handle_ptrace_exit_event was
  // run (or the replay equivalent) or we recognized that the task is already
  // dead and we cleaned up our books so we don't try to destroy our buffers
  // or anything like that in an already deceased task.
  // We might defer handling the exit (e.g. if there's an ongoing execve).
  // If this is true, `seen_ptrace_exit_event` must be true.
  bool handled_ptrace_exit_event_;

  // A counter for the number of stops for which the stop may have been caused
  // by PTRACE_INTERRUPT. See description in do_waitpid
  int expecting_ptrace_interrupt_stop;

  bool was_reaped_;
  // Let this Task object be destroyed with no consequences.
  bool forgotten;

  Task(Task&) = delete;
  Task operator=(Task&) = delete;
};

} // namespace rr

#endif /* RR_TASK_H_ */
