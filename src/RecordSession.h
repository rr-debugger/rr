/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_RECORD_SESSION_H_
#define RR_RECORD_SESSION_H_

#include <string>
#include <vector>

#include "Scheduler.h"
#include "SeccompFilterRewriter.h"
#include "Session.h"
#include "ThreadGroup.h"
#include "TraceFrame.h"
#include "WaitStatus.h"

namespace rr {

class RecordTask;

struct DisableCPUIDFeatures {
  DisableCPUIDFeatures()
    : features_ecx(0)
    , features_edx(0)
    , extended_features_ebx(0)
    , extended_features_ecx(0)
    , extended_features_edx(0)
    , xsave_features_eax(0)
  {}
  bool any_features_disabled() const {
    return features_ecx || features_edx || extended_features_ebx
      || extended_features_ecx || extended_features_edx || xsave_features_eax;
  }
  /**
   * Includes disabling TSX and other rr-incompatible features */
  void amend_cpuid_data(uint32_t eax_in, uint32_t ecx_in,
                        CPUIDData* cpuid_data) const;

  /* in: EAX=0x01 */
  uint32_t features_ecx;
  uint32_t features_edx;
  /* in: EAX=0x07 ECX=0 */
  uint32_t extended_features_ebx;
  uint32_t extended_features_ecx;
  uint32_t extended_features_edx;
  /* in: EAX=0x0D ECX=1 */
  uint32_t xsave_features_eax;
};

/** Encapsulates additional session state related to recording. */
class RecordSession : public Session {
public:
  typedef std::shared_ptr<RecordSession> shr_ptr;

  /**
   * Create a recording session for the initial command line |argv|.
   */
  enum SyscallBuffering { ENABLE_SYSCALL_BUF, DISABLE_SYSCALL_BUF };
  static shr_ptr create(
      const std::vector<std::string>& argv,
      const std::vector<std::string>& extra_env,
      const DisableCPUIDFeatures& features,
      SyscallBuffering syscallbuf = ENABLE_SYSCALL_BUF,
      BindCPU bind_cpu = BIND_CPU);

  const DisableCPUIDFeatures& disable_cpuid_features() const {
    return disable_cpuid_features_;
  }
  bool use_syscall_buffer() const { return use_syscall_buffer_; }
  size_t syscall_buffer_size() const { return syscall_buffer_size_; }
  bool use_read_cloning() const { return use_read_cloning_; }
  bool use_file_cloning() const { return use_file_cloning_; }
  void set_ignore_sig(int sig) { ignore_sig = sig; }
  int get_ignore_sig() const { return ignore_sig; }
  void set_continue_through_sig(int sig) { continue_through_sig = sig; }
  int get_continue_through_sig() const { return continue_through_sig; }

  enum RecordStatus {
    // Some execution was recorded. record_step() can be called again.
    STEP_CONTINUE,
    // All tracees are dead. record_step() should not be called again.
    STEP_EXITED,
    // Spawning the initial tracee failed. An error message will be in
    // failure_message.
    STEP_SPAWN_FAILED
  };
  struct RecordResult {
    RecordStatus status;
    // When status == STEP_EXITED
    WaitStatus exit_status;
    // When status == STEP_SPAWN_FAILED
    std::string failure_message;
  };
  /**
   * Record some tracee execution.
   * This may block. If blocking is interrupted by a signal, will return
   * STEP_CONTINUE.
   * Typically you'd call this in a loop until it returns something other than
   * STEP_CONTINUE.
   * Note that when this returns, some tasks may be running (not in a ptrace-
   * stop). In particular, up to one task may be executing user code and any
   * number of tasks may be blocked in syscalls.
   */
  RecordResult record_step();

  /**
   * Flush buffers and write a termination record to the trace. Don't call
   * record_step() after this.
   */
  void terminate_recording();

  virtual RecordSession* as_record() override { return this; }

  TraceWriter& trace_writer() { return trace_out; }

  virtual void on_destroy(Task* t) override;

  Scheduler& scheduler() { return scheduler_; }

  SeccompFilterRewriter& seccomp_filter_rewriter() {
    return seccomp_filter_rewriter_;
  }

  enum ContinueType { DONT_CONTINUE = 0, CONTINUE, CONTINUE_SYSCALL };

  struct StepState {
    // Continue with this continuation type.
    ContinueType continue_type;
    StepState(ContinueType continue_type) : continue_type(continue_type) {}
  };

  void set_enable_chaos(bool enable_chaos) {
    scheduler().set_enable_chaos(enable_chaos);
    this->enable_chaos_ = enable_chaos;
  }
  bool enable_chaos() const { return enable_chaos_; }

  void set_use_read_cloning(bool enable) { use_read_cloning_ = enable; }
  void set_use_file_cloning(bool enable) { use_file_cloning_ = enable; }
  void set_syscall_buffer_size(size_t size) { syscall_buffer_size_ = size; }

  void set_wait_for_all(bool wait_for_all) {
    this->wait_for_all_ = wait_for_all;
  }

  virtual Task* new_task(pid_t tid, pid_t rec_tid, uint32_t serial,
                         SupportedArch a) override;

  RecordTask* find_task(pid_t rec_tid) const;
  RecordTask* find_task(const TaskUid& tuid) const;

  /**
   * This gets called when we detect that a task has been revived from the
   * dead with a PTRACE_EVENT_EXEC. See ptrace man page under "execve(2) under
   * ptrace" for the horrid details.
   *
   * The task in the thread-group that triggered the successful execve has changed
   * its tid to |rec_tid|. We mirror that, and emit TraceTaskEvents to make it
   * look like a new task was spawned and the old task exited.
   */
  RecordTask* revive_task_for_exec(pid_t rec_tid);

private:
  RecordSession(const std::string& exe_path,
                const std::vector<std::string>& argv,
                const std::vector<std::string>& envp,
                const DisableCPUIDFeatures& features,
                SyscallBuffering syscallbuf, BindCPU bind_cpu);

  virtual void on_create(Task* t) override;

  void handle_seccomp_traced_syscall(RecordTask* t,
                                     RecordSession::StepState* step_state,
                                     RecordResult* result,
                                     bool* did_enter_syscall);
  // Returns false if the task exits during processing
  bool process_syscall_entry(RecordTask* t, StepState* step_state,
                             RecordResult* step_result,
                             SupportedArch syscall_arch);
  void check_initial_task_syscalls(RecordTask* t, RecordResult* step_result);
  bool handle_ptrace_event(RecordTask** t_ptr, StepState* step_state,
                           RecordResult* result, bool* did_enter_syscall);
  bool handle_signal_event(RecordTask* t, StepState* step_state);
  void runnable_state_changed(RecordTask* t, StepState* step_state,
                              RecordResult* step_result,
                              bool can_consume_wait_status);
  void signal_state_changed(RecordTask* t, StepState* step_state);
  void syscall_state_changed(RecordTask* t, StepState* step_state);
  void desched_state_changed(RecordTask* t);
  bool prepare_to_inject_signal(RecordTask* t, StepState* step_state);
  void task_continue(const StepState& step_state);
  bool can_end();

  TraceWriter trace_out;
  Scheduler scheduler_;
  ThreadGroup::shr_ptr initial_thread_group;
  SeccompFilterRewriter seccomp_filter_rewriter_;

  DisableCPUIDFeatures disable_cpuid_features_;
  int ignore_sig;
  int continue_through_sig;
  Switchable last_task_switchable;
  size_t syscall_buffer_size_;
  bool use_syscall_buffer_;

  bool use_file_cloning_;
  bool use_read_cloning_;
  /**
   * When true, try to increase the probability of finding bugs.
   */
  bool enable_chaos_;
  /**
   * When true, wait for all tracees to exit before finishing recording.
   */
  bool wait_for_all_;
};

} // namespace rr

#endif // RR_RECORD_SESSION_H_
