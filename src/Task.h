/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_TASK_H_
#define RR_TASK_H_

#include <asm/ldt.h>

#include <memory>
#include <vector>

#include "preload/preload_interface.h"

#include "AddressSpace.h"
#include "Event.h"
#include "ExtraRegisters.h"
#include "FdTable.h"
#include "PerfCounters.h"
#include "PropertyTable.h"
#include "Registers.h"
#include "TaskishUid.h"
#include "TraceStream.h"
#include "WaitStatus.h"
#include "core.h"
#include "kernel_abi.h"
#include "kernel_supplement.h"
#include "remote_code_ptr.h"
#include "util.h"

struct syscallbuf_hdr;
struct syscallbuf_record;
struct user_desc;

namespace rr {

class AutoRemoteSyscalls;
class RecordSession;
class RecordTask;
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
  RESUME_SYSEMU = PTRACE_SYSEMU,
  RESUME_SYSEMU_SINGLESTEP = PTRACE_SYSEMU_SINGLESTEP,
};
enum WaitRequest {
  // After resuming, blocking-waitpid() until tracee status
  // changes.
  RESUME_WAIT,
  // Don't wait after resuming.
  RESUME_NONBLOCKING
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
  typedef std::vector<WatchConfig> DebugRegs;

  /**
   * We hide the destructor and require clients to call this instead. This
   * lets us make virtual calls from within the destruction code. This
   * does the actual PTRACE_DETACH and then calls the real destructor.
   */
  void destroy();

  /**
   * This must be in an emulated syscall, entered through
   * |cont_sysemu()| or |cont_sysemu_singlestep()|, but that's
   * not checked.  If so, step over the system call instruction
   * to "exit" the emulated syscall.
   */
  void finish_emulated_syscall();

  size_t syscallbuf_data_size() {
    return read_mem(REMOTE_PTR_FIELD(syscallbuf_child, num_rec_bytes)) +
           sizeof(struct syscallbuf_hdr);
  }

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
   * Stat |fd| in the context of this task's fd table.
   */
  struct stat stat_fd(int fd);
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
   * Force the wait status of this to |status|, as if
   * |wait()/try_wait()| had returned it. Call this whenever a waitpid
   * returned activity for this past.
   */
  void did_waitpid(WaitStatus status);

  /**
   * Syscalls have side effects on registers (e.g. setting the flags register).
   * Perform those side effects on |registers| to make it look like a syscall
   * happened.
   */
  void canonicalize_regs(SupportedArch syscall_arch);

  /**
   * Return the ptrace message pid associated with the current ptrace
   * event, f.e. the new child's pid at PTRACE_EVENT_CLONE.
   */
  template <typename T> T get_ptrace_eventmsg() {
    unsigned long msg = 0;
    xptrace(PTRACE_GETEVENTMSG, nullptr, &msg);
    return T(msg);
  }

  /**
   * Return the siginfo at the signal-stop of this.
   * Not meaningful unless this is actually at a signal stop.
   */
  const siginfo_t& get_siginfo();

  /**
   * Destroy in the tracee task the scratch buffer and syscallbuf (if
   * syscallbuf_child is non-null).
   * This task must already be at a state in which remote syscalls can be
   * executed; if it's not, results are undefined.
   */
  void destroy_buffers();

  void unmap_buffers_for(
      AutoRemoteSyscalls& remote, Task* t,
      remote_ptr<struct syscallbuf_hdr> saved_syscallbuf_child);
  void close_buffers_for(AutoRemoteSyscalls& remote, Task* t);

  remote_ptr<const struct syscallbuf_record> next_syscallbuf_record();
  long stored_record_size(remote_ptr<const struct syscallbuf_record> record);

  /** Return the current $ip of this. */
  remote_code_ptr ip() { return regs().ip(); }

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
    auto t = AddressSpace::rr_page_syscall_from_exit_point(ip());
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
   * Only RecordTasks actually change pid namespaces.
   */
  virtual pid_t own_namespace_tid() { return tid; }

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
   */
  void enter_syscall();

  /**
   * We have observed entry to a syscall (either by PTRACE_EVENT_SECCOMP or
   * a syscall, depending on the value of Session::syscall_seccomp_ordering()).
   * Continue into the kernel to perform the syscall and stop at the
   * PTRACE_SYSCALL syscall-exit trap. Returns false if we see the process exit
   * before that.
   */
  bool exit_syscall();

  /**
   * Return the "task name"; i.e. what |prctl(PR_GET_NAME)| or
   * /proc/tid/comm would say that the task's name is.
   */
  const std::string& name() const { return prname; }

  /**
   * Call this method when this task has just performed an |execve()|
   * (so we're in the new address space), but before the system call has
   * returned.
   */
  void post_exec(const std::string& exe_file);

  /**
   * Call this method when this task has exited a successful execve() syscall.
   * At this point it is safe to make remote syscalls.
   */
  void post_exec_syscall();

  /**
   * Return true if this task has execed.
   */
  bool execed() const;

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

  /** Return the extra registers of this. */
  const ExtraRegisters& extra_regs();

  /** Return the current arch of this. This can change due to exec(). */
  SupportedArch arch() const {
    // Use 'registers' directly instead of calling regs(), since this can
    // be called while the task is not stopped.
    return registers.arch();
  }

  /**
   * Return the debug status (DR6 on x86). The debug status is always cleared
   * in resume_execution() before we resume, so it always only reflects the
   * events since the last resume.
   */
  uintptr_t debug_status();
  /**
   * Set the debug status (DR6 on x86).
   */
  void set_debug_status(uintptr_t status);

  /**
   * Determine why a SIGTRAP occurred. Uses debug_status() but doesn't
   * consume it.
   */
  TrapReasons compute_trap_reasons();

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
   * this address space.
   */
  std::string read_c_str(remote_ptr<char> child_addr);

  /**
   * Resume execution |how|, deliverying |sig| if nonzero.
   * After resuming, |wait_how|. In replay, reset hpcs and
   * request a tick period of tick_period. The default value
   * of tick_period is 0, which means effectively infinite.
   * If interrupt_after_elapsed is nonzero, we interrupt the task
   * after that many seconds have elapsed.
   *
   * All tracee execution goes through here.
   */
  void resume_execution(ResumeRequest how, WaitRequest wait_how,
                        TicksRequest tick_period, int sig = 0);

  /** Return the session this is part of. */
  Session& session() const { return *session_; }

  /** Set the tracee's registers to |regs|. Lazy. */
  void set_regs(const Registers& regs);

  /** Ensure registers are flushed back to the underlying task. */
  void flush_regs();

  /** Set the tracee's extra registers to |regs|. */
  void set_extra_regs(const ExtraRegisters& regs);

  /**
   * Program the debug registers to the vector of watchpoint
   * configurations in |reg| (also updating the debug control
   * register appropriately).  Return true if all registers were
   * successfully programmed, false otherwise.  Any time false
   * is returned, the caller is guaranteed that no watchpoint
   * has been enabled; either all of |regs| is enabled and true
   * is returned, or none are and false is returned.
   */
  bool set_debug_regs(const DebugRegs& regs);

  uintptr_t get_debug_reg(size_t regno);
  void set_debug_reg(size_t regno, uintptr_t value);

  /** Update the thread area to |addr|. */
  void set_thread_area(remote_ptr<struct ::user_desc> tls);

  /** Set the thread area at index `idx` to desc and reflect this
    * into the OS task. Returns 0 on success, errno otherwise.
    */
  int emulate_set_thread_area(int idx, struct ::user_desc desc);

  /** Get the thread area from the remote process.
    * Returns 0 on success, errno otherwise.
    */
  int emulate_get_thread_area(int idx, struct ::user_desc& desc);

  const std::vector<struct ::user_desc>& thread_areas() {
    return thread_areas_;
  }

  void set_status(WaitStatus status) { wait_status = status; }

  /**
   * Return true when the task is running, false if it's stopped.
   */
  bool is_running() const { return !is_stopped; }

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
  uint32_t trace_time() const;

  /**
   * Call this after the tracee successfully makes a
   * |prctl(PR_SET_NAME)| call to change the task name to the
   * string pointed at in the tracee's address space by
   * |child_addr|.
   */
  void update_prname(remote_ptr<void> child_addr);

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
   * with the process in a stopped() state. If interrupt_after_elapsed > 0,
   * interrupt the task after that many seconds have elapsed.
   */
  void wait(double interrupt_after_elapsed = 0);
  /**
   * Return true if the status of this has changed, but don't
   * block.
   */
  bool try_wait();
  /**
   * Return true if an unexpected exit was already detected for this task and
   * it is ready to be reported.
   */
  bool wait_unexpected_exit();

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
  void write_mem(remote_ptr<T> child_addr, const T* val, int count) {
    DEBUG_ASSERT(type_has_no_holes<T>());
    write_bytes_helper(child_addr, sizeof(*val) * count,
                       static_cast<const void*>(val));
  }

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
  void write_bytes_helper(remote_ptr<void> addr, ssize_t buf_size,
                          const void* buf, bool* ok = nullptr,
                          uint32_t flags = 0);

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
   * first.
   * This never fails. If necessary we force the tracee to open the file
   * itself and smuggle the fd back to us.
   */
  void open_mem_fd();

  /**
   * Calls open_mem_fd if this task's AddressSpace doesn't already have one.
   */
  void open_mem_fd_if_needed();

  /* True when any assumptions made about the status of this
   * process have been invalidated, and must be re-established
   * with a waitpid() call. Only applies to tasks which are dying, usually
   * due to a signal sent to the entire thread group. */
  bool unstable;
  /* exit(), or exit_group() with one task, has been called, so
   * the exit can be treated as stable. */
  bool stable_exit;

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

  PerfCounters hpc;

  /* This is always the "real" tid of the tracee. */
  pid_t tid;
  /* This is always the recorded tid of the tracee.  During
   * recording, it's synonymous with |tid|, and during replay
   * it's the tid that was recorded. */
  pid_t rec_tid;

  size_t syscallbuf_size;
  /* Points at the tracee's mapping of the buffer. */
  remote_ptr<struct syscallbuf_hdr> syscallbuf_child;
  // XXX Move these fields to ReplayTask
  remote_code_ptr stopping_breakpoint_table;
  int stopping_breakpoint_table_entry_size;

  remote_ptr<struct preload_globals> preload_globals;
  typedef uint8_t ThreadLocals[PRELOAD_THREAD_LOCALS_SIZE];
  ThreadLocals thread_locals;

  PropertyTable& properties() { return properties_; }

  size_t usable_scratch_size() {
    return std::max<ssize_t>(0, scratch_size - page_size());
  }
  remote_ptr<void> syscallbuf_alt_stack() {
    return scratch_ptr.is_null() ? remote_ptr<void>()
                                 : scratch_ptr + scratch_size;
  }
  void setup_preload_thread_locals();
  const ThreadLocals& fetch_preload_thread_locals();
  void activate_preload_thread_locals();

  struct CapturedState {
    Ticks ticks;
    Registers regs;
    ExtraRegisters extra_regs;
    std::string prname;
    std::vector<struct user_desc> thread_areas;
    remote_ptr<struct syscallbuf_hdr> syscallbuf_child;
    size_t syscallbuf_size;
    size_t num_syscallbuf_bytes;
    remote_ptr<struct preload_globals> preload_globals;
    remote_ptr<void> scratch_ptr;
    ssize_t scratch_size;
    remote_ptr<void> top_of_stack;
    uint64_t cloned_file_data_offset;
    ThreadLocals thread_locals;
    pid_t rec_tid;
    uint32_t serial;
    int desched_fd_child;
    int cloned_file_data_fd_child;
    WaitStatus wait_status;
  };

  /**
   * Lock or unlock the syscallbuf to prevent the preload library from using it.
   * Only has an effect if the syscallbuf has been initialized.
   */
  void set_syscallbuf_locked(bool locked);

  /**
   * Like |fallible_ptrace()| but infallible for most purposes.
   * Errors other than ESRCH are treated as fatal. Returns false if
   * we got ESRCH. This can happen any time during recording when the
   * task gets a SIGKILL from outside.
   */
  bool ptrace_if_alive(int request, remote_ptr<void> addr, void* data);

  bool is_dying() const {
    return seen_ptrace_exit_event || detected_unexpected_exit;
  }

  remote_code_ptr last_execution_resume() const {
    return address_of_last_execution_resume;
  }

protected:
  Task(Session& session, pid_t tid, pid_t rec_tid, uint32_t serial,
       SupportedArch a);
  virtual ~Task();

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
                      Session* other_session = nullptr);

  /**
   * Internal method called after the first wait() during a clone().
   */
  virtual void post_wait_clone(Task*, int) {}

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
   * Make the ptrace |request| with |addr| and |data|, return
   * the ptrace return value.
   */
  long fallible_ptrace(int request, remote_ptr<void> addr, void* data);

  /**
   * Like |fallible_ptrace()| but completely infallible.
   * All errors are treated as fatal.
   */
  void xptrace(int request, remote_ptr<void> addr, void* data);

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
  Task* os_fork_into(Session* session);
  static Task* os_clone_into(const CapturedState& state,
                             AutoRemoteSyscalls& remote);

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
                        remote_ptr<void> stack = nullptr,
                        remote_ptr<int> ptid = nullptr,
                        remote_ptr<void> tls = nullptr,
                        remote_ptr<int> ctid = nullptr);

  /**
   * Fork and exec the initial task. If something goes wrong later
   * (i.e. an exec does not occur before an exit), an error may be
   * readable from the other end of the pipe whose write end is error_fd.
   */
  static Task* spawn(Session& session, const ScopedFd& error_fd,
                     ScopedFd* sock_fd_out, int* tracee_socket_fd_number_out,
                     const TraceStream& trace, const std::string& exe_path,
                     const std::vector<std::string>& argv,
                     const std::vector<std::string>& envp, pid_t rec_tid = -1);

  void maybe_workaround_singlestep_bug();

  void* preload_thread_locals();

  uint32_t serial;
  // The address space of this task.
  AddressSpace::shr_ptr as;
  // The file descriptor table of this task.
  FdTable::shr_ptr fds;
  // Task's OS name.
  std::string prname;
  // Count of all ticks seen by this task since tracees became
  // consistent and the task last wait()ed.
  Ticks ticks;
  // When |is_stopped|, these are our child registers.
  Registers registers;
  // Where we last resumed execution
  remote_code_ptr address_of_last_execution_resume;
  ResumeRequest how_last_execution_resumed;
  // In certain circumstances, due to hardware bugs, we need to fudge the
  // cx register. If so, we record the orginal value here. See comments in
  // Task.cc
  uint64_t last_resume_orig_cx;
  // True when we know via waitpid() that the task is stopped and we haven't
  // resumed it.
  bool is_stopped;
  /* True when the seccomp filter has been enabled via prctl(). This happens
   * in the first system call issued by the initial tracee (after it returns
   * from kill(SIGSTOP) to synchronize with the tracer). */
  bool seccomp_bpf_enabled;
  // True when we consumed a PTRACE_EVENT_EXIT that was about to race with
  // a resume_execution, that was issued while stopped (i.e. SIGKILL).
  bool detected_unexpected_exit;
  // True when 'registers' has changes that haven't been flushed back to the
  // task yet.
  bool registers_dirty;
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
  std::vector<struct user_desc> thread_areas_;
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
  bool seen_ptrace_exit_event;

  PropertyTable properties_;

  // A counter for the number of stops for which the stop may have been caused
  // by PTRACE_INTERRUPT. See description in do_waitpid
  int expecting_ptrace_interrupt_stop;

  Task(Task&) = delete;
  Task operator=(Task&) = delete;
};

} // namespace rr

#endif /* RR_TASK_H_ */
