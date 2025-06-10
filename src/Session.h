/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_SESSION_H_
#define RR_SESSION_H_

#include <cassert>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include "AddressSpace.h"
#include "MonitoredSharedMemory.h"
#include "Task.h"
#include "TaskishUid.h"
#include "TraceStream.h"
#include "preload/preload_interface.h"

namespace rr {

class AddressSpace;
class DiversionSession;
class EmuFs;
class RecordSession;
class ReplaySession;
class ReplayTask;
class Task;
class ThreadGroup;
class AutoRemoteSyscalls;

struct CloneCompletion {
  struct AddressSpaceClone {
    Task* clone_leader;
    Task::CapturedState clone_leader_state;
    std::vector<Task::CapturedState> member_states;
    std::vector<std::pair<remote_ptr<void>, std::vector<uint8_t>>>
        captured_memory;
  };
  std::vector<AddressSpaceClone> address_spaces;
  Task::ClonedFdTables cloned_fd_tables;
};

// The following types are used by step() APIs in Session subclasses.

/**
 * Stores a Task and information about it separately so decisions can
 * still be made from a Task's context even if it dies.
 */
struct TaskContext {
  TaskContext()
      : task(nullptr),
        session(nullptr),
        thread_group(nullptr) {}
  explicit TaskContext(Task* task)
      : task(task),
        session(task ? &task->session() : nullptr),
        thread_group(task ? task->thread_group() : nullptr) {}
  TaskContext(Session* session, std::shared_ptr<ThreadGroup> thread_group)
      : task(nullptr),
        session(session),
        thread_group(thread_group) {}

  // A pointer to a task. This may be |nullptr|. When non-NULL, this
  // is not necessarily the same as session->current_task() (for
  // example, when replay switches to a new task after
  // ReplaySession::replay_step()).
  Task* task;
  // The session to which |task| belongs/belonged.
  Session* session;
  // The thread group to which |task| belongs/belonged.
  std::shared_ptr<ThreadGroup> thread_group;
};

/**
 * In general, multiple break reasons can apply simultaneously.
 */
struct BreakStatus {
  BreakStatus()
      : task_context(TaskContext()),
        breakpoint_hit(false),
        singlestep_complete(false),
        approaching_ticks_target(false),
        task_exit(false) {}
  BreakStatus(const BreakStatus& other)
      : task_context(other.task_context),
        watchpoints_hit(other.watchpoints_hit),
        signal(other.signal
                   ? std::unique_ptr<siginfo_t>(new siginfo_t(*other.signal))
                   : nullptr),
        breakpoint_hit(other.breakpoint_hit),
        singlestep_complete(other.singlestep_complete),
        approaching_ticks_target(other.approaching_ticks_target),
        task_exit(other.task_exit) {}
  const BreakStatus& operator=(const BreakStatus& other) {
    task_context = other.task_context;
    watchpoints_hit = other.watchpoints_hit;
    signal = other.signal
                 ? std::unique_ptr<siginfo_t>(new siginfo_t(*other.signal))
                 : nullptr;
    breakpoint_hit = other.breakpoint_hit;
    singlestep_complete = other.singlestep_complete;
    approaching_ticks_target = other.approaching_ticks_target;
    task_exit = other.task_exit;
    return *this;
  }

  // The triggering TaskContext.
  TaskContext task_context;
  // List of watchpoints hit; any watchpoint hit causes a stop after the
  // instruction that triggered the watchpoint has completed.
  std::vector<WatchConfig> watchpoints_hit;
  // When non-null, we stopped because a signal was delivered to |task|.
  std::unique_ptr<siginfo_t> signal;
  // True when we stopped because we hit a software breakpoint at |task|'s
  // current ip().
  bool breakpoint_hit;
  // True when we stopped because a singlestep completed in |task|.
  bool singlestep_complete;
  // True when we stopped because we got too close to the specified ticks
  // target.
  bool approaching_ticks_target;
  // True when we stopped because |task| is about to exit.
  bool task_exit;

  // True when we stopped because we hit a software or hardware breakpoint at
  // |task|'s current ip().
  bool hardware_or_software_breakpoint_hit() {
    for (const auto& w : watchpoints_hit) {
      // Hardware execution watchpoints behave like breakpoints: the CPU
      // stops before the instruction is executed.
      if (w.type == WATCH_EXEC) {
        return true;
      }
    }
    return breakpoint_hit;
  }
  // Returns just the data watchpoints hit.
  std::vector<WatchConfig> data_watchpoints_hit() {
    std::vector<WatchConfig> result;
    for (const auto& w : watchpoints_hit) {
      if (w.type != WATCH_EXEC) {
        result.push_back(w);
      }
    }
    return result;
  }

  bool any_break() {
    return !watchpoints_hit.empty() || signal || breakpoint_hit ||
           singlestep_complete || approaching_ticks_target;
  }

  Task* task() const { return task_context.task; }
};
enum RunCommand {
  // Continue until we hit a breakpoint or a new replay event
  RUN_CONTINUE,
  // Execute a single instruction (unless at a breakpoint or a replay event)
  RUN_SINGLESTEP,
  // Like RUN_SINGLESTEP, but a single-instruction loop is allowed (but not
  // required) to execute multiple times if we don't reach a different
  // instruction. Usable with ReplaySession::replay_step only.
  RUN_SINGLESTEP_FAST_FORWARD
};

inline bool is_singlestep(RunCommand command) {
  return command == RUN_SINGLESTEP || command == RUN_SINGLESTEP_FAST_FORWARD;
}

/**
 * Sessions track the global state of a set of tracees corresponding
 * to an rr recorder or replayer.  During recording, the tracked
 * tracees will all write to the same TraceWriter, and during
 * replay, the tracees that will be tracked will all be created based
 * on the same TraceReader.
 *
 * Multiple sessions can coexist in the same process.  This
 * is required when using replay checkpoints, for example.
 */
class Session {
  friend class ReplaySession;

public:
  // AddressSpaces and ThreadGroups are indexed by their first task's TaskUid
  // (effectively), so that if the first task dies and its tid is recycled,
  // we don't get confused. TaskMap is indexed by tid since there can never be
  // two Tasks with the same tid at the same time.
  typedef std::map<AddressSpaceUid, AddressSpace*> AddressSpaceMap;
  typedef std::map<pid_t, Task*> TaskMap;
  typedef std::map<ThreadGroupUid, ThreadGroup*> ThreadGroupMap;

  /**
   * Call |post_exec()| immediately after a tracee has successfully
   * |execve()|'d.  After that, |done_initial_exec()| returns true.
   * This is called while we're still in the execve syscall so it's not safe
   * to perform remote syscalls in this method.
   *
   * Tracee state can't be validated before the first exec,
   * because the address space inside the rr process for |rr
   * replay| will be different than it was for |rr record|.
   * After the first exec, we're running tracee code, and
   * everything must be the same.
   */
  void post_exec();

  /**
   * Returns true after the tracee has done the initial exec in Task::spawn.
   * Before then, tracee state can be inconsistent; from the exec exit-event
   * onwards, the tracee state much be consistent.
   */
  bool done_initial_exec() const { return done_initial_exec_; }

  /**
   * Create and return a new address space that's constructed
   * from |t|'s actual OS address space. When spawning, |exe| is the empty
   * string; it will be replaced during the first execve(), when we first
   * start running real tracee code.
   */
  std::shared_ptr<AddressSpace> create_vm(
      Task* t, const std::string& exe = std::string(), uint32_t exec_count = 0);
  /**
   * Return a copy of |vm| with the same mappings.  If any
   * mapping is changed, only the |clone()|d copy is updated,
   * not its origin (i.e. copy-on-write semantics).
   */
  std::shared_ptr<AddressSpace> clone(Task* t,
                                      std::shared_ptr<AddressSpace> vm);
  /**
   * Create the initial thread group.
   */
  std::shared_ptr<ThreadGroup> create_initial_tg(Task* t);
  /**
   * Return a copy of |tg| with the same mappings.
   */
  std::shared_ptr<ThreadGroup> clone(Task* t, std::shared_ptr<ThreadGroup> tg);

  /** See Task::clone(). */
  Task* clone(Task* p, int flags, remote_ptr<void> stack, remote_ptr<void> tls,
              remote_ptr<int> cleartid_addr, pid_t new_tid,
              pid_t new_rec_tid = -1);

  uint32_t next_task_serial() { return next_task_serial_++; }

  uint32_t current_task_serial() const { return next_task_serial_; }

  /**
   * Return the task created with |rec_tid|, or nullptr if no such
   * task exists.
   */
  Task* find_task(pid_t rec_tid) const;

  Task* find_task(const TaskUid& tuid) const;

  /**
   * Return the thread group whose unique ID is |tguid|, or nullptr if no such
   * thread group exists.
   */
  ThreadGroup* find_thread_group(const ThreadGroupUid& tguid) const;

  /**
   * Find the thread group for a specific pid
   */
  ThreadGroup* find_thread_group(pid_t pid) const;

  /**
   * Return the AddressSpace whose unique ID is |vmuid|, or nullptr if no such
   * address space exists.
   */
  AddressSpace* find_address_space(const AddressSpaceUid& vmuid) const;

  /**
   * |tasks().size()| will be zero and all the OS tasks will be
   * gone when this returns, or this won't return.
   */
  void kill_all_tasks();

  /**
   * Call these functions from the objects' destructors in order
   * to notify this session that the objects are dying.
   */
  void on_destroy(AddressSpace* vm);
  void on_destroy(Task* t);
  void on_create(ThreadGroup* tg);
  void on_destroy(ThreadGroup* tg);

  /** Return the set of Tasks being traced in this session. */
  const TaskMap& tasks() const {
    finish_initializing();
    return task_map;
  }

  /**
   * Return the set of AddressSpaces being tracked in this session.
   */
  std::vector<AddressSpace*> vms() const;

  virtual RecordSession* as_record() { return nullptr; }
  virtual ReplaySession* as_replay() { return nullptr; }
  virtual DiversionSession* as_diversion() { return nullptr; }

  bool is_recording() { return as_record() != nullptr; }
  bool is_replaying() { return as_replay() != nullptr; }
  bool is_diversion() { return as_diversion() != nullptr; }

  // Indicate if execution should be "visible", i.e. it's the main
  // session of a recording or a replay whose output could be echoed.
  void set_visible_execution(bool visible) { visible_execution_ = visible; }

  virtual bool need_performance_counters() const { return true; }

  struct Statistics {
    Statistics()
        : bytes_written(0), ticks_processed(0), syscalls_performed(0) {}
    uint64_t bytes_written;
    Ticks ticks_processed;
    uint32_t syscalls_performed;
  };
  void accumulate_bytes_written(uint64_t bytes_written) {
    statistics_.bytes_written += bytes_written;
  }
  void accumulate_syscall_performed() { statistics_.syscalls_performed += 1; }
  void accumulate_ticks_processed(Ticks ticks) {
    statistics_.ticks_processed += ticks;
  }
  Statistics statistics() { return statistics_; }

  virtual Task* new_task(pid_t tid, pid_t rec_tid, uint32_t serial,
                         SupportedArch a, const std::string& name);

  std::string read_spawned_task_error() const;

  /* Returns an empty mapping if the tracee died.
   * If map_address is non-null then we must use that address in the tracee,
   * otherwise we select the address.
   */
  static KernelMapping create_shared_mmap(
      AutoRemoteSyscalls& remote, size_t size, remote_ptr<void> required_child_addr,
      const char* name, int tracee_prot = PROT_READ | PROT_WRITE,
      int tracee_flags = 0,
      MonitoredSharedMemory::shr_ptr monitored = nullptr);

  static void make_private_shared(AutoRemoteSyscalls& remote,
                                  const AddressSpace::Mapping m);
  enum PreserveContents {
    PRESERVE_CONTENTS,
    DISCARD_CONTENTS,
  };
  // Recreate an mmap region that is shared between rr and the tracee. The
  // caller is responsible for recreating the data in the new mmap, if `preserve` is
  // DISCARD_CONTENTS.
  // OK to call this while 'm' references one of the mappings in remote's
  // AddressSpace.
  // Returns an empty Mapping if the tracee died unexpectedly.
  static const AddressSpace::Mapping recreate_shared_mmap(
      AutoRemoteSyscalls& remote, const AddressSpace::Mapping& m,
      PreserveContents preserve = DISCARD_CONTENTS,
      MonitoredSharedMemory::shr_ptr monitored = nullptr);

  /* Takes a mapping and replaces it by one that is shared between rr and
     the tracee. The caller is responsible for filling the contents of the
      new mapping.
      Returns an empty mapping if the tracee unexpectedly died.
   */
  static AddressSpace::Mapping steal_mapping(
      AutoRemoteSyscalls& remote, const AddressSpace::Mapping& m,
      MonitoredSharedMemory::shr_ptr monitored = nullptr);

  enum PtraceSyscallBeforeSeccomp {
    PTRACE_SYSCALL_BEFORE_SECCOMP,
    SECCOMP_BEFORE_PTRACE_SYSCALL,
    PTRACE_SYSCALL_BEFORE_SECCOMP_UNKNOWN,
  };
  PtraceSyscallBeforeSeccomp syscall_seccomp_ordering() {
    return syscall_seccomp_ordering_;
  }

  static bool has_cpuid_faulting();
  static const char* rr_mapping_prefix();

  ScopedFd& tracee_socket_fd() { return *tracee_socket; }
  // Before using this, it must be drained. See AutoRemoteSyscalls.
  ScopedFd& tracee_socket_receiver_fd() { return *tracee_socket_receiver; }
  int tracee_fd_number() const { return tracee_socket_fd_number; }

  virtual TraceStream* trace_stream() { return nullptr; }
  TicksSemantics ticks_semantics() const { return ticks_semantics_; }

  virtual int cpu_binding() const;

  int syscall_number_for_rrcall_init_preload() const {
    return SYS_rrcall_init_preload - RR_CALL_BASE + rrcall_base_;
  }
  int syscall_number_for_rrcall_init_buffers() const {
    return SYS_rrcall_init_buffers - RR_CALL_BASE + rrcall_base_;
  }
  int syscall_number_for_rrcall_notify_syscall_hook_exit() const {
    return SYS_rrcall_notify_syscall_hook_exit - RR_CALL_BASE + rrcall_base_;
  }
  int syscall_number_for_rrcall_notify_control_msg() const {
    return SYS_rrcall_notify_control_msg - RR_CALL_BASE + rrcall_base_;
  }
  int syscall_number_for_rrcall_reload_auxv() const {
    return SYS_rrcall_reload_auxv - RR_CALL_BASE + rrcall_base_;
  }
  int syscall_number_for_rrcall_mprotect_record() const {
    return SYS_rrcall_mprotect_record - RR_CALL_BASE + rrcall_base_;
  }
  int syscall_number_for_rrcall_notify_stap_semaphore_added() const {
    return SYS_rrcall_notify_stap_semaphore_added - RR_CALL_BASE + rrcall_base_;
  }
  int syscall_number_for_rrcall_notify_stap_semaphore_removed() const {
    return SYS_rrcall_notify_stap_semaphore_removed - RR_CALL_BASE + rrcall_base_;
  }
  int syscall_number_for_rrcall_rdtsc() const {
    return SYS_rrcall_rdtsc - RR_CALL_BASE + rrcall_base_;
  }
  uint32_t syscallbuf_fds_disabled_size() const {
    return syscallbuf_fds_disabled_size_;
  }
  uint32_t syscallbuf_hdr_size() const {
    return syscallbuf_hdr_size_;
  }

  /* Bind the current process to the a CPU as specified in the session options
     or trace */
  void do_bind_cpu();

  cpu_set_t original_affinity() const { return original_affinity_; }

  const ThreadGroupMap& thread_group_map() const { return thread_group_map_; }

  virtual int tracee_output_fd(int dflt) {
    return dflt;
  }

  void set_intel_pt_enabled(bool intel_pt) { intel_pt_ = intel_pt; }
  /* When this is true, we collect Intel PT traces during recording
     or replay. */
  bool intel_pt_enabled() const { return intel_pt_; }

  virtual bool mark_stdio() const;

protected:
  Session();
  virtual ~Session();

  ScopedFd create_spawn_task_error_pipe();

  Session(const Session& other);
  Session& operator=(const Session&) = delete;

  virtual void on_create(Task* t);

  BreakStatus diagnose_debugger_trap(Task* t, RunCommand run_command);
  void check_for_watchpoint_changes(Task* t, BreakStatus& break_status);

  void copy_state_to(Session& dest, EmuFs& emu_fs, EmuFs& dest_emu_fs);

  // Call this before doing anything that requires access to the full set
  // of tasks (i.e., almost anything!). Not really const!
  void finish_initializing() const;
  void assert_fully_initialized() const;

  AddressSpaceMap vm_map;
  TaskMap task_map;
  ThreadGroupMap thread_group_map_;

  ScopedFd cpu_lock;

  // If non-null, data required to finish initializing the tasks of this
  // session.
  std::unique_ptr<CloneCompletion> clone_completion;

  Statistics statistics_;

  std::shared_ptr<ScopedFd> tracee_socket;
  std::shared_ptr<ScopedFd> tracee_socket_receiver;
  int tracee_socket_fd_number;
  uint32_t next_task_serial_;
  ScopedFd spawned_task_error_fd_;

  int rrcall_base_;
  uint32_t syscallbuf_fds_disabled_size_;
  uint32_t syscallbuf_hdr_size_;
  PtraceSyscallBeforeSeccomp syscall_seccomp_ordering_;

  TicksSemantics ticks_semantics_;

  cpu_set_t original_affinity_;

  /**
   * True if we've done an exec so tracees are now in a state that will be
   * consistent across record and replay.
   */
  bool done_initial_exec_;

  /**
   * True while the execution of this session is visible to users.
   */
  bool visible_execution_;

  /**
   * True while we're collecting Intel PT data.
   */
  bool intel_pt_;
};

} // namespace rr

#endif // RR_SESSION_H_
