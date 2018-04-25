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
#include "TaskishUid.h"
#include "TraceStream.h"

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

// The following types are used by step() APIs in Session subclasses.

/**
 * In general, multiple break reasons can apply simultaneously.
 */
struct BreakStatus {
  BreakStatus()
      : task(nullptr),
        breakpoint_hit(false),
        singlestep_complete(false),
        approaching_ticks_target(false),
        task_exit(false) {}
  BreakStatus(const BreakStatus& other)
      : task(other.task),
        watchpoints_hit(other.watchpoints_hit),
        signal(other.signal
                   ? std::unique_ptr<siginfo_t>(new siginfo_t(*other.signal))
                   : nullptr),
        breakpoint_hit(other.breakpoint_hit),
        singlestep_complete(other.singlestep_complete),
        approaching_ticks_target(other.approaching_ticks_target),
        task_exit(other.task_exit) {}
  const BreakStatus& operator=(const BreakStatus& other) {
    task = other.task;
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

  // The triggering Task. This may be different from session->current_task()
  // when replay switches to a new task when ReplaySession::replay_step() ends.
  Task* task;
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
  virtual void on_destroy(Task* t);
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

  bool visible_execution() const { return visible_execution_; }
  void set_visible_execution(bool visible) { visible_execution_ = visible; }

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
                         SupportedArch a);

  std::string read_spawned_task_error() const;

  static KernelMapping create_shared_mmap(
      AutoRemoteSyscalls& remote, size_t size, remote_ptr<void> map_hint,
      const char* name, int tracee_prot = PROT_READ | PROT_WRITE,
      int tracee_flags = 0,
      MonitoredSharedMemory::shr_ptr&& monitored = nullptr);

  static bool make_private_shared(AutoRemoteSyscalls& remote,
                                  const AddressSpace::Mapping m);
  enum PreserveContents {
    PRESERVE_CONTENTS,
    DISCARD_CONTENTS,
  };
  // Recreate an mmap region that is shared between rr and the tracee. The
  // caller
  // is responsible for recreating the data in the new mmap, if `preserve` is
  // DISCARD_CONTENTS.
  // OK to call this while 'm' references one of the mappings in remote's
  // AddressSpace
  static const AddressSpace::Mapping& recreate_shared_mmap(
      AutoRemoteSyscalls& remote, const AddressSpace::Mapping& m,
      PreserveContents preserve = DISCARD_CONTENTS,
      MonitoredSharedMemory::shr_ptr&& monitored = nullptr);

  /* Takes a mapping and replaces it by one that is shared between rr and
     the tracee. The caller is responsible for filling the contents of the
      new mapping. */
  static const AddressSpace::Mapping& steal_mapping(
      AutoRemoteSyscalls& remote, const AddressSpace::Mapping& m,
      MonitoredSharedMemory::shr_ptr&& monitored = nullptr);

  enum PtraceSyscallBeforeSeccomp {
    PTRACE_SYSCALL_BEFORE_SECCOMP,
    SECCOMP_BEFORE_PTRACE_SYSCALL,
    PTRACE_SYSCALL_BEFORE_SECCOMP_UNKNOWN,
  };
  PtraceSyscallBeforeSeccomp syscall_seccomp_ordering() {
    return syscall_seccomp_ordering_;
  }
  bool has_cpuid_faulting() const { return has_cpuid_faulting_; }

  static const char* rr_mapping_prefix();

  ScopedFd& tracee_socket_fd() { return *tracee_socket; }
  int tracee_fd_number() const { return tracee_socket_fd_number; }

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

  // XXX Move CloneCompletion/CaptureState etc to ReplayTask/ReplaySession
  struct CloneCompletion;
  // Call this before doing anything that requires access to the full set
  // of tasks (i.e., almost anything!). Not really const!
  void finish_initializing() const;
  void assert_fully_initialized() const;

  AddressSpaceMap vm_map;
  TaskMap task_map;
  ThreadGroupMap thread_group_map;

  // If non-null, data required to finish initializing the tasks of this
  // session.
  std::unique_ptr<CloneCompletion> clone_completion;

  Statistics statistics_;

  std::shared_ptr<ScopedFd> tracee_socket;
  int tracee_socket_fd_number;
  uint32_t next_task_serial_;
  ScopedFd spawned_task_error_fd_;

  PtraceSyscallBeforeSeccomp syscall_seccomp_ordering_;

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
   * True if ARCH_GET/SET_CPUID are supported on this system.
   */
  bool has_cpuid_faulting_;
};

} // namespace rr

#endif // RR_SESSION_H_
