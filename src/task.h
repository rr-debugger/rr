/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_TASK_H_
#define RR_TASK_H_

#include <memory>
#include <vector>

#include "preload/preload_interface.h"

#include "AddressSpace.h"
#include "Event.h"
#include "ExtraRegisters.h"
#include "FdTable.h"
#include "kernel_abi.h"
#include "kernel_supplement.h"
#include "PerfCounters.h"
#include "PropertyTable.h"
#include "Registers.h"
#include "remote_code_ptr.h"
#include "TaskishUid.h"
#include "TraceStream.h"
#include "util.h"

class AutoRemoteSyscalls;
class RecordSession;
class ReplaySession;
class ScopedFd;
class Session;
struct Sighandlers;
class Task;

struct syscallbuf_hdr;
struct syscallbuf_record;

/**
 * A list of return addresses extracted from the stack. The tuple
 * (perfcounter ticks, regs, return addresses) may be needed to disambiguate
 * states that aren't unique in (perfcounter ticks, regs).
 * When return addresses can't be extracted, some suffix of the list may be
 * all zeroes.
 */
struct ReturnAddressList {
  enum { COUNT = 8 };
  remote_ptr<void> addresses[COUNT];

  bool operator==(const ReturnAddressList& other) const {
    for (int i = 0; i < COUNT; ++i) {
      if (addresses[i] != other.addresses[i]) {
        return false;
      }
    }
    return true;
  }
  bool operator!=(const ReturnAddressList& other) const {
    return !(*this == other);
  }
};

/**
 * Tracks a group of tasks with an associated ID, set from the
 * original "thread group leader", the child of |fork()| which became
 * the ancestor of all other threads in the group.  Each constituent
 * task must own a reference to this.
 */
class TaskGroup : public HasTaskSet {
public:
  TaskGroup(Session* session, TaskGroup* parent, pid_t tgid, pid_t real_tgid,
            uint32_t serial);
  ~TaskGroup();

  typedef std::shared_ptr<TaskGroup> shr_ptr;

  /** See |Task::destabilize_task_group()|. */
  void destabilize();

  const pid_t tgid;
  const pid_t real_tgid;

  int exit_code;

  Session* session() const { return session_; }
  void forget_session() { session_ = nullptr; }

  TaskGroup* parent() { return parent_; }

  TaskGroupUid tguid() const { return TaskGroupUid(tgid, serial); }

  // We don't allow tasks to make themselves undumpable. If they try,
  // record that here and lie about it if necessary.
  bool dumpable;

private:
  TaskGroup(const TaskGroup&) = delete;
  TaskGroup operator=(const TaskGroup&) = delete;

  Session* session_;
  /** Parent TaskGroup, or nullptr if it's not a tracee (rr or init). */
  TaskGroup* parent_;

  std::set<TaskGroup*> children;

  uint32_t serial;
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
  RESUME_UNLIMITED_TICKS = -1
  // Positive values are a request for an interrupt
  // after that number of ticks
};

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

  ~Task();

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
   * This must be in an emulated syscall, entered through
   * |cont_sysemu()| or |cont_sysemu_singlestep()|, but that's
   * not checked.  If so, step over the system call instruction
   * to "exit" the emulated syscall.
   */
  void finish_emulated_syscall();

  /**
   * Shortcut to the most recent |pending_event->desched.rec| when
   * there's a desched event on the stack, and nullptr otherwise.
   * Exists just so that clients don't need to dig around in the
   * event stack to find this record.
   */
  const struct syscallbuf_record* desched_rec() const;

  /**
   * Returns true when the task is in a signal handler in an interrupted
   * system call being handled by syscall buffering.
   */
  bool running_inside_desched() const;

  size_t syscallbuf_data_size() const {
    return syscallbuf_hdr->num_rec_bytes + sizeof(*syscallbuf_hdr);
  }

  /**
   * Mark the members of this task's group as "unstable",
   * meaning that even though a task may look runnable, it
   * actually might not be.  (And so |waitpid(-1)| should be
   * used to schedule the next task.)
   *
   * This is needed to handle the peculiarities of mass Task
   * death at exit_group() and upon receiving core-dumping
   * signals.  The reason it's needed is easier to understand if
   * you keep in mind that the "main loop" of ptrace tracers is
   * /supposed/ to look like
   *
   *   while (true) {
   *     int tid = waitpid(-1, ...);
   *     // do something with tid
   *     ptrace(tid, PTRACE_SYSCALL, ...);
   *   }
   *
   * That is, the tracer is supposed to let the kernel schedule
   * threads and then respond to notifications generated by the
   * kernel.
   *
   * Obviously this isn't how rr's recorder loop looks, because,
   * among other things, rr has to serialize thread execution.
   * Normally this isn't much of a problem.  However, mass task
   * death is an exception.  What happens at a mass task death
   * is a sequence of events like the following
   *
   *  1. A task calls exit_group() or is sent a core-dumping
   *     signal.
   *  2. rr receives a PTRACE_EVENT_EXIT notification for the
   *     task.
   *  3. rr detaches from the dying/dead task.
   *  4. Successive calls to waitpid(-1) generate additional
   *     PTRACE_EVENT_EXIT notifications for each also-dead task
   *     in the original task's thread group.  Repeat (2) / (3)
   *     for each notified task.
   *
   * So why destabilization?  After (2), rr can't block on the
   * task shutting down (|waitpid(tid)|), because the kernel
   * harvests the LWPs of the dying task group in an unknown
   * order (which we shouldn't assume, even if we could guess
   * it).  If rr blocks on the task harvest, it will (usually)
   * deadlock.
   *
   * And because rr doesn't know the order of tasks that will be
   * reaped, it doesn't know which of the dying tasks to
   * "schedule".  If it guesses and blocks on another task in
   * the group's status-change, it will (usually) deadlock.
   *
   * So destabilizing a task group, from rr's perspective, means
   * handing scheduling control back to the kernel and not
   * trying to harvest tasks before detaching from them.
   *
   * NB: an invariant of rr scheduling is that all process
   * status changes happen as a result of rr resuming the
   * execution of a task.  This is required to keep tracees in
   * known states, preventing events from happening "behind rr's
   * back".  However, destabilizing a task group means that
   * these kinds of changes are possible, in theory.
   *
   * Currently, instability is a one-way street; it's only used
   * needed for death signals and exit_group().
   */
  void destabilize_task_group();

  /**
   * Emulate 'tracer' ptracing this task.
   */
  void set_emulated_ptracer(Task* tracer);

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
   * Called when this task is able to receive a SIGCHLD (e.g. because
   * we completed delivery of a signal already). Sends a new synthetic
   * SIGCHLD to the task if there are still ptraced tasks that need a SIGCHLD
   * sent for them.
   */
  void send_synthetic_SIGCHLD_if_necessary();
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
  bool is_waiting_for_ptrace(Task* t);

  /**
   * Returns true if this task is in a waitpid or similar that would return
   * when t's status changes due to a regular event (exit).
   */
  bool is_waiting_for(Task* t);

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
   * Set tick count to 'count'.
   */
  void set_tick_count(Ticks count);

  /**
   * Return true if this exited because of a SYS_exit/exit_group
   * call.
   */
  bool exited() const { return WIFEXITED(wait_status); }

  /** Return the event at the top of this's stack. */
  Event& ev() { return pending_events.back(); }
  const Event& ev() const { return pending_events.back(); }

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
   * If override_siginfo is non-null and status indicates a pending signal,
   * use *override_siginfo as the siginfo instead of reading it from the kernel.
   */
  void did_waitpid(int status, siginfo_t* override_siginfo = nullptr);

  /**
   * Syscalls have side effects on registers (e.g. setting the flags register).
   * Perform those side effects on |regs| and do set_regs() on that to make it
   * look like a syscall happened.
   */
  void emulate_syscall_entry(const Registers& regs);

  /**
   * Wait for |futex| in this address space to have the value
   * |val|.
   *
   * WARNING: this implementation semi-busy-waits for the value
   * change.  This must only be used in contexts where the futex
   * will change "soon".
   */
  void futex_wait(remote_ptr<int> futex, int val);

  /**
   * Return the ptrace message pid associated with the current ptrace
   * event, f.e. the new child's pid at PTRACE_EVENT_CLONE.
   */
  pid_t get_ptrace_eventmsg_pid();

  uint16_t get_ptrace_eventmsg_seccomp_data();

  /**
   * Return the siginfo at the signal-stop of this.
   * Not meaningful unless this is actually at a signal stop.
   */
  const siginfo_t& get_siginfo();

  /**
   * Set the siginfo for the signal-stop of this.
   */
  void set_siginfo(const siginfo_t& si);

  /**
   * Return the trace we're either recording to (|trace_reader()|)
   * or replaying from (|trace_writer()|).
   */
  TraceReader& trace_reader();
  TraceWriter& trace_writer();

  /**
   * Initialize tracee buffers in this, i.e., implement
   * RRCALL_init_syscall_buffer.  This task must be at the point
   * of *exit from* the rrcall.  Registers will be updated with
   * the return value from the rrcall, which is also returned
   * from this call.  |map_hint| suggests where to map the
   * region; see |init_syscallbuf_buffer()|.
   *
   * Pass SHARE_DESCHED_EVENT_FD to additionally share that fd.
   */
  void init_buffers(remote_ptr<void> map_hint);

  /**
   * Destroy in the tracee task the scratch buffer and syscallbuf (if
   * syscallbuf_child is non-null).
   * This task must already be at a state in which remote syscalls can be
   * executed; if it's not, results are undefined.
   */
  void destroy_buffers();

  /** Return the current $ip of this. */
  remote_code_ptr ip() { return regs().ip(); }

  /**
   * Return true if this is at an arm-desched-event syscall.
   */
  bool is_arm_desched_event_syscall();

  /**
   * Return true if this is at an arm-desched-event or
   * disarm-desched-event syscall.
   */
  bool is_desched_event_syscall();

  /**
   * Return true if this is at a disarm-desched-event syscall.
   */
  bool is_disarm_desched_event_syscall();

  /**
   * Return true when this is just before a syscall trap
   * instruction for a traced syscall made by the syscallbuf
   * code. Callers may assume |is_in_syscallbuf()| is implied
   * by this.
   */
  bool is_entering_traced_syscall() {
    return ip() == as->traced_syscall_ip() ||
           ip() == as->privileged_traced_syscall_ip();
  }

  /**
   * Return true if this is within the syscallbuf library.  This
   * *does not* imply that $ip is at a buffered syscall; see
   * below.
   */
  bool is_in_syscallbuf() {
    remote_ptr<void> p = ip().to_data_ptr<void>();
    return (as->syscallbuf_lib_start() <= p && p < as->syscallbuf_lib_end()) ||
           (as->rr_page_start() <= p && p < as->rr_page_end());
  }

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

  /**
   * Return true when this task is in an untraced syscall, i.e. one
   * initiated by a function in the syscallbuf. Callers may
   * assume |is_in_syscallbuf()| is implied by this. Note that once we've
   * entered the traced syscall, ip() is immediately after the syscall
   * instruction.
   */
  bool is_in_untraced_syscall() {
    return ip() == AddressSpace::rr_page_ip_in_untraced_syscall() ||
           ip() == AddressSpace::rr_page_ip_in_untraced_replayed_syscall() ||
           ip() == AddressSpace::rr_page_ip_in_privileged_untraced_syscall();
  }

  /**
   * Return true if |ptrace_event()| is the trace event
   * generated by the syscallbuf seccomp-bpf when a traced
   * syscall is entered.
   */
  bool is_ptrace_seccomp_event() const;

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

  /** Dump all pending events to the INFO log. */
  void log_pending_events() const;

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
   * Call this hook just before exiting a syscall.  Often Task
   * attributes need to be updated based on the finishing syscall.
   * Use 'regs' instead of this->regs() because some registers may not be
   * set properly in the task yet.
   */
  void on_syscall_exit(int syscallno, const Registers& regs);

  /**
   * Assuming ip() is just past a breakpoint instruction, adjust
   * ip() backwards to point at that breakpoint insn.
   */
  void move_ip_before_breakpoint();

  /**
   * Assuming we've just entered a syscall, exit that syscall and reset
   * state to reenter the syscall just as it was called the first time.
   */
  void exit_syscall_and_prepare_restart();

  /**
   * Resume execution until we get a syscall entry or exit event.
   * During recording, any signals received are stashed.
   * seccomp events are ignored; we assume this syscall is under rr's control.
   */
  void advance_syscall();

  /**
   * Return the "task name"; i.e. what |prctl(PR_GET_NAME)| or
   * /proc/tid/comm would say that the task's name is.
   */
  const std::string& name() const { return prname; }

  /**
   * Call this method when this task has just performed an |execve()|
   * (so we're in the new address space), but before the system call has
   * returned.
   * During replay replay_regs is non-null and contains the register values
   * recorded immediately after the exec.
   */
  void post_exec(const Registers* replay_regs = nullptr,
                 const ExtraRegisters* replay_extra_regs = nullptr,
                 const std::string* replay_exe = nullptr);

  /**
   * Call this method when this task has exited a successful execve() syscall.
   * At this point it is safe to make remote syscalls.
   * |event| is the TraceTaskEvent (EXEC) that will be recorded or is being
   * replayed.
   */
  void post_exec_syscall(TraceTaskEvent& event);

  /**
   * Manage pending events.  |push_event()| pushes the given
   * event onto the top of the event stack.  The |pop_*()|
   * helpers pop the event at top of the stack, which must be of
   * the specified type.
   */
  void push_event(const Event& ev) { pending_events.push_back(ev); }
  void pop_event(EventType expected_type);
  void pop_noop() { pop_event(EV_NOOP); }
  void pop_desched() { pop_event(EV_DESCHED); }
  void pop_signal_delivery() { pop_event(EV_SIGNAL_DELIVERY); }
  void pop_signal_handler() { pop_event(EV_SIGNAL_HANDLER); }
  void pop_syscall() { pop_event(EV_SYSCALL); }
  void pop_syscall_interruption() { pop_event(EV_SYSCALL_INTERRUPTION); }

  /**
   * Read |N| bytes from |child_addr| into |buf|, or don't
   * return.
   */
  template <size_t N>
  void read_bytes(remote_ptr<void> child_addr, uint8_t(&buf)[N]) {
    return read_bytes_helper(child_addr, N, buf);
  }

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

  void record_remote_str(remote_ptr<void> str);

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

  enum {
    /* The x86 linux 3.5.0-36 kernel packaged with Ubuntu
     * 12.04 has been observed to mutate $esi across
     * syscall entry/exit.  (This has been verified
     * outside of rr as well; not an rr bug.)  It's not
     * clear whether this is a ptrace bug or a kernel bug,
     * but either way it's not supposed to happen.  So we
     * allow validate_args to cover up that bug. */
    IGNORE_ESI = 0x01
  };
  /** Assert that the current register values match the values in the
   *  current trace record.
   */
  void validate_regs(uint32_t flags = 0);

  /**
   * Capture return addresses from this task's stack. The returned
   * address list may not be actual return addresses (in optimized code,
   * will probably not be), but they will be a function of the task's current
   * state, so may be useful for distinguishing this state from other states.
   */
  ReturnAddressList return_addresses();

  /**
   * Return the debug status, which is a bitfield comprising
   * |DebugStatus| bits (see above).
   */
  uintptr_t debug_status();
  /**
   * Return the debug status, which is a bitfield comprising
   * |DebugStatus| bits (see above), and clear the kernel state.
   */
  uintptr_t consume_debug_status();
  void replace_debug_status(uintptr_t status);

  /**
   * Return the address of the watchpoint programmed at slot
   * |i|.
   */
  remote_ptr<void> watchpoint_addr(size_t i);

  /** Return the current $sp of this. */
  remote_ptr<void> sp() { return regs().sp(); }

  /**
   * Read |val| from |child_addr|.
   * If the data can't all be read, then if |ok| is non-null
   * sets *ok to false, otherwise asserts.
   */
  template <typename T>
  T read_mem(remote_ptr<T> child_addr, bool* ok = nullptr) {
    T val;
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
  std::string read_c_str(remote_ptr<void> child_addr);

  /**
   * Copy |num_bytes| from |src| to |dst| in the address space
   * of this.
   */
  void remote_memcpy(remote_ptr<void> dst, remote_ptr<void> src,
                     size_t num_bytes);

  template <typename T>
  void remote_memcpy(remote_ptr<T> dst, remote_ptr<T> src) {
    remote_memcpy(dst, src, sizeof(T));
  }

  /**
   * Resume execution |how|, deliverying |sig| if nonzero.
   * After resuming, |wait_how|. In replay, reset hpcs and
   * request a tick period of tick_period. The default value
   * of tick_period is 0, which means effectively infinite.
   *
   * You probably want to use one of the cont*() helpers above,
   * and not this.
   */
  void resume_execution(ResumeRequest how, WaitRequest wait_how,
                        TicksRequest tick_period, int sig = 0);

  /** Return the session this is part of. */
  Session& session() const { return *session_; }
  RecordSession& record_session() const;
  ReplaySession& replay_session() const;

  const TraceFrame& current_trace_frame();

  /** Restore the next chunk of saved data from the trace to this. */
  ssize_t set_data_from_trace();

  /** Restore all remaining chunks of saved data for the current trace frame. */
  void apply_all_data_records_from_trace();

  /**
   * Set the syscall-return-value register of this to what was
   * saved in the current trace frame.
   */
  void set_return_value_from_trace();

  /** Set the tracee's registers to |regs|. */
  void set_regs(const Registers& regs);

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

  /**
   * Reads the value of the given debug register.
   */
  uintptr_t get_debug_reg(size_t regno);

  /**
   * Update the futex robust list head pointer to |list| (which
   * is of size |len|).
   */
  void set_robust_list(remote_ptr<void> list, size_t len) {
    robust_futex_list = list;
    robust_futex_list_len = len;
  }
  remote_ptr<void> robust_list() const { return robust_futex_list; }
  size_t robust_list_len() const { return robust_futex_list_len; }

  /** Update the thread area to |addr|. */
  void set_thread_area(remote_ptr<struct user_desc> tls);

  const std::vector<struct user_desc>& thread_areas() { return thread_areas_; }

  /** Update the clear-tid futex to |tid_addr|. */
  void set_tid_addr(remote_ptr<int> tid_addr);
  remote_ptr<int> tid_addr() { return tid_futex; }

  /**
   * Call this after |sig| is delivered to this task.  Emulate
   * sighandler updates induced by the signal delivery.
   */
  void signal_delivered(int sig);

  /** Return true if this died because of a signal. */
  bool signaled() const { return WIFSIGNALED(wait_status); }

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
  void stash_synthetic_sig(const siginfo_t& si);
  bool has_stashed_sig() const { return !stashed_signals.empty(); }
  siginfo_t peek_stash_sig();
  void pop_stash_sig();

  /**
   * When a signal triggers an emulated a ptrace-stop for this task,
   * save the siginfo so a later emulated ptrace-continue with this signal
   * number can use it.
   */
  void save_ptrace_signal_siginfo(const siginfo_t& si);
  /**
   * When emulating a ptrace-continue with a signal number, extract the siginfo
   * that was saved by |save_ptrace_signal_siginfo|. If no such siginfo was
   * saved, make one up.
   */
  siginfo_t take_ptrace_signal_siginfo(int sig);

  /**
   * Return true when the task is running, false if it's stopped.
   */
  bool is_running() const { return !is_stopped; }

  /**
   * Return the status of this as of the last successful
   * wait()/try_wait() call.
   */
  int status() const { return wait_status; }

  /**
   * Return true if this is at a signal-stop.  If so,
   * |stop_sig()| returns the signal that stopped us.
   */
  bool stopped() const { return stopped_from_status(wait_status); }
  int stop_sig() const { return stop_sig_from_status(wait_status); }

  /**
   * Return the ptrace event as of the last call to
   * |wait()/try_wait()|.
   */
  int ptrace_event() const { return ptrace_event_from_status(wait_status); }

  /**
   * Return the signal that's pending for this as of the last
   * call to |wait()/try_wait()|.  The signal 0 means "no
   * signals'.
   */
  int pending_sig() const { return pending_sig_from_status(wait_status); }

  void clear_wait_status() { wait_status = 0; }

  /** Return the task group this belongs to. */
  TaskGroup::shr_ptr task_group() { return tg; }

  /** Return the id of this task's recorded thread group. */
  pid_t tgid() const { return tg->tgid; }
  /** Return id of real OS task group. */
  pid_t real_tgid() const { return tg->real_tgid; }

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
   * Call this when SYS_sigaction is finishing with |regs|.
   */
  void update_sigaction(const Registers& regs);

  /**
   * Call this when the tracee is about to complete a
   * SYS_rt_sigprocmask syscall with |regs|.
   */
  void update_sigmask(const Registers& regs);

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

  enum AllowInterrupt {
    ALLOW_INTERRUPT,
    // Pass this when the caller has already triggered a ptrace stop
    // and wait() must not trigger a new one.
    DONT_ALLOW_INTERRUPT
  };
  /**
   * Block until the status of this changes. wait() expects the wait to end
   * with the process in a stopped() state.
   */
  void wait(AllowInterrupt allow_interrupt = ALLOW_INTERRUPT);
  /**
   * Return true if the status of this has changed, but don't
   * block.
   */
  bool try_wait();

  /**
   * Currently we don't allow recording across uid changes, so we can just
   * return rr's uid.
   */
  uid_t getuid() { return ::getuid(); }

  /**
   * Write |N| bytes from |buf| to |child_addr|, or don't return.
   */
  template <size_t N>
  void write_bytes(remote_ptr<void> child_addr, const uint8_t(&buf)[N]) {
    write_bytes_helper(child_addr, N, buf);
  }

  /**
   * Write |val| to |child_addr|.
   */
  template <typename T>
  void write_mem(remote_ptr<T> child_addr, const T& val, bool* ok = nullptr) {
    assert(type_has_no_holes<T>());
    write_bytes_helper(child_addr, sizeof(val), static_cast<const void*>(&val),
                       ok);
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
    assert(type_has_no_holes<T>());
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
  void write_bytes_helper(remote_ptr<void> addr, ssize_t buf_size,
                          const void* buf, bool* ok = nullptr);

  /** See |pending_sig()| above. */
  int pending_sig_from_status(int status) const;
  /** See |ptrace_event()| above. */
  static int ptrace_event_from_status(int status) {
    return (0xFF0000 & status) >> 16;
  }
  /** See |stopped()| and |stop_sig()| above. */
  static bool stopped_from_status(int status) { return WIFSTOPPED(status); }
  int stop_sig_from_status(int status) const;

  /**
   * Call this when performing a clone syscall in this task. Returns
   * true if the call completed, false if it was interrupted and
   * needs to be resumed. When the call returns true, the task is
   * stopped at a PTRACE_EVENT_CLONE or PTRACE_EVENT_FORK.
   */
  bool clone_syscall_is_complete();

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
   * Called when SYS_rrcall_init_preload has happened.
   */
  void at_preload_init();

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

  /**
   * Do a tgkill to send a specific signal to this task.
   */
  void tgkill(int sig);

  /**
   * Return the name of the given syscall.
   */
  std::string syscall_name(int syscallno) const;

  /* State only used during recording. */

  /* True when this is switchable for semantic purposes, but
   * definitely isn't blocked on ony resource.  In that case,
   * it's safe for the scheduler to do a blocking waitpid on
   * this if our scheduling slot is open. */
  bool pseudo_blocked;
  /* Number of times this context has been scheduled in a row,
   * which approximately corresponds to the number of events
   * it's processed in succession.  The scheduler maintains this
   * state and uses it to make scheduling decisions. */
  uint32_t succ_event_counter;
  /* True when any assumptions made about the status of this
   * process have been invalidated, and must be re-established
   * with a waitpid() call. Only applies to tasks which are dying, usually
   * due to a signal sent to the entire task group. */
  bool unstable;
  /* exit(), or exit_group() with one task, has been called, so
   * the exit can be treated as stable. */
  bool stable_exit;
  /* Task 'nice' value set by setpriority(2).
     We use this to drive scheduling decisions. rr's scheduler is
     deliberately simple and unfair; a task never runs as long as there's
     another runnable task with a lower nice value. */
  int priority;
  /* Tasks with in_round_robin_queue set are in the session's
   * in_round_robin_queue instead of its task_priority_set.
   */
  bool in_round_robin_queue;
  // The set of signals that were blocked during a sigsuspend. Only present
  // during the first EV_SIGNAL during an interrupted sigsuspend.
  std::unique_ptr<sig_set_t> sigsuspend_blocked_sigs;
  // If not NOT_STOPPED, then the task is logically stopped and this is the type
  // of stop.
  EmulatedStopType emulated_stop_type;
  // If not 0, then a CLOCK_MONOTONIC time (in seconds) at which this
  // task is expected to wake from a system call (if not interrupted earlier).
  double sleeping_until;

  // Task for which we're emulating ptrace of this task, or null
  Task* emulated_ptracer;
  // true if this task needs to send a SIGCHLD to its ptracer for its
  // emulated ptrace stop
  bool emulated_ptrace_SIGCHLD_pending;
  // if nonzero, code to deliver to ptracer when it waits
  int emulated_ptrace_stop_code;
  std::set<Task*> emulated_ptrace_tracees;

  WaitType in_wait_type;
  pid_t in_wait_pid;

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
  ssize_t scratch_size;

  /* Nonzero after the trace recorder has flushed the
   * syscallbuf.  When this happens, the recorder must prepare a
   * "reset" of the buffer, to zero the record count, at the
   * next available slow (taking |desched| into
   * consideration). */
  bool flushed_syscallbuf;
  /* Value of hdr->num_rec_bytes when the buffer was flushed */
  uint32_t flushed_num_rec_bytes;
  /* This bit is set when code wants to prevent the syscall
   * record buffer from being reset when it normally would be.
   * Currently, the desched'd syscall code uses this. */
  bool delay_syscallbuf_reset;

  /* The child's desched counter event fd number, and our local
   * dup. */
  ScopedFd desched_fd;
  int desched_fd_child;
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

  /* State used during both recording and replay. */

  PerfCounters hpc;

  /* This is always the "real" tid of the tracee. */
  pid_t tid;
  /* This is always the recorded tid of the tracee.  During
   * recording, it's synonymous with |tid|, and during replay
   * it's the tid that was recorded. */
  pid_t rec_tid;
  /* This is the recorded tid of the tracee *in its own pid namespace*.
   * Only valid during recording, otherwise 0!
   */
  pid_t own_namespace_rec_tid;

  /* Points at rr's mapping of the (shared) syscall buffer. */
  struct syscallbuf_hdr* syscallbuf_hdr;
  size_t num_syscallbuf_bytes;
  /* Points at the tracee's mapping of the buffer. */
  remote_ptr<struct syscallbuf_hdr> syscallbuf_child;
  remote_ptr<char> syscallbuf_fds_disabled_child;
  remote_code_ptr stopping_breakpoint_table;
  int stopping_breakpoint_table_entry_size;

  PropertyTable& properties() { return properties_; }

  struct CapturedState {
    pid_t rec_tid;
    uint32_t serial;
    Registers regs;
    ExtraRegisters extra_regs;
    std::string prname;
    remote_ptr<void> robust_futex_list;
    size_t robust_futex_list_len;
    std::vector<struct user_desc> thread_areas;
    size_t num_syscallbuf_bytes;
    int desched_fd_child;
    remote_ptr<struct syscallbuf_hdr> syscallbuf_child;
    std::vector<uint8_t> syscallbuf_hdr;
    remote_ptr<char> syscallbuf_fds_disabled_child;
    remote_ptr<void> scratch_ptr;
    ssize_t scratch_size;
    int wait_status;
    sig_set_t blocked_sigs;
    std::deque<Event> pending_events;
    Ticks ticks;
    remote_ptr<int> tid_futex;
    remote_ptr<void> top_of_stack;
  };

private:
  Task(Session& session, pid_t tid, pid_t rec_tid, uint32_t serial,
       int priority, SupportedArch a);

  template <typename Arch>
  void on_syscall_exit_arch(int syscallno, const Registers& regs);

  /** Helper function for update_sigaction. */
  template <typename Arch> void update_sigaction_arch(const Registers& regs);

  /** Helper function for init_buffers. */
  template <typename Arch> void init_buffers_arch(remote_ptr<void> map_hint);

  /**
   * Return a new Task cloned from |p|.  |flags| are a set of
   * CloneFlags (see above) that determine which resources are
   * shared or copied to the new child.  |new_tid| is the tid
   * assigned to the new task by the kernel.  |new_rec_tid| is
   * only relevant to replay, and is the pid that was assigned
   * to the task during recording.
   */
  Task* clone(int flags, remote_ptr<void> stack, remote_ptr<void> tls,
              remote_ptr<int> cleartid_addr, pid_t new_tid, pid_t new_rec_tid,
              uint32_t new_serial, Session* other_session = nullptr);

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
   * Destroy tracer-side state of this (as opposed to remote,
   * tracee-side state).
   */
  void destroy_local_buffers();

  /**
   * Make the ptrace |request| with |addr| and |data|, return
   * the ptrace return value.
   */
  long fallible_ptrace(int request, remote_ptr<void> addr, void* data);

  /**
   * Like |fallible_ptrace()| but infallible for most purposes.
   * Errors other than ESRCH are treated as fatal. Returns false if
   * we got ESRCH. This can happen any time during recording when the
   * task gets a SIGKILL from outside.
   */
  bool ptrace_if_alive(int request, remote_ptr<void> addr, void* data);

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
  void init_syscall_buffer(AutoRemoteSyscalls& remote,
                           remote_ptr<void> map_hint);

  /**
   * True if this has blocked delivery of the desched signal.
   */
  bool is_desched_sig_blocked();

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
  static Task* os_clone_into(const CapturedState& state, Task* task_leader,
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
  static Task* os_clone(Task* parent, Session* session,
                        AutoRemoteSyscalls& remote, pid_t rec_child_tid,
                        uint32_t new_serial, unsigned base_flags,
                        remote_ptr<void> stack = nullptr,
                        remote_ptr<int> ptid = nullptr,
                        remote_ptr<void> tls = nullptr,
                        remote_ptr<int> ctid = nullptr);

  /** Fork and exec a task to run |ae|, with |rec_tid|. */
  static Task* spawn(Session& session, const TraceStream& trace,
                     pid_t rec_tid = -1);

  uint32_t serial;
  // The address space of this task.
  AddressSpace::shr_ptr as;
  // The file descriptor table of this task.
  FdTable::shr_ptr fds;
  // The set of signals that are currently blocked.
  sig_set_t blocked_sigs;
  // The current stack of events being processed.  (We use a
  // deque instead of a stack because we need to iterate the
  // events.)
  std::deque<Event> pending_events;
  // Task's OS name.
  std::string prname;
  // Count of all ticks seen by this task since tracees became
  // consistent and the task last wait()ed.
  Ticks ticks;
  // When |is_stopped|, these are our child registers.
  Registers registers;
  // True when we know via waitpid() that the task is stopped and we haven't
  // resumed it.
  bool is_stopped;
  // True when there was a breakpoint set at the location where we resumed
  // execution
  bool breakpoint_set_where_execution_resumed;
  // When |extra_registers_known|, we have saved our extra registers.
  ExtraRegisters extra_registers;
  bool extra_registers_known;
  // Futex list passed to |set_robust_list()|.  We could keep a
  // strong type for this list head and read it if we wanted to,
  // but for now we only need to remember its address / size at
  // the time of the most recent set_robust_list() call.
  remote_ptr<void> robust_futex_list;
  size_t robust_futex_list_len;
  // The session we're part of.
  Session* session_;
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
  // Stashed signal-delivery state, ready to be delivered at
  // next opportunity.
  std::deque<siginfo_t> stashed_signals;
  // Saved emulated-ptrace signals
  std::vector<siginfo_t> saved_ptrace_siginfos;
  // The task group this belongs to.
  std::shared_ptr<TaskGroup> tg;
  // Entries set by |set_thread_area()| or the |tls| argument to |clone()|
  // (when that's a user_desc). May be more than one due to different
  // entry_numbers.
  std::vector<struct user_desc> thread_areas_;
  // The memory cell the kernel will clear and notify on exit,
  // if our clone parent requested it.
  remote_ptr<int> tid_futex;
  // The |stack| argument passed to |clone()|, which for
  // "threads" is the top of the user-allocated stack.
  remote_ptr<void> top_of_stack;
  // The most recent status of this task as returned by
  // waitpid().
  int wait_status;
  // The most recent siginfo (captured when wait_status shows pending_sig())
  siginfo_t pending_siginfo;
  // True when a PTRACE_EXIT_EVENT has been observed in the wait_status
  // for this task.
  bool seen_ptrace_exit_event;

  PropertyTable properties_;

  Task(Task&) = delete;
  Task operator=(Task&) = delete;
};

#endif /* RR_TASK_H_ */
