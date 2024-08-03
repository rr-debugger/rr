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
#include "TraceStream.h"
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

struct TraceUuid {
  uint8_t bytes[16];
};

/** Encapsulates additional session state related to recording. */
class RecordSession final : public Session {
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
      const TraceOutputPath& path_info,
      SyscallBuffering syscallbuf = ENABLE_SYSCALL_BUF,
      unsigned char syscallbuf_desched_sig = SIGPWR,
      BindCPU bind_cpu = BIND_CPU,
      const TraceUuid* trace_id = nullptr,
      bool use_audit = false,
      bool unmap_vdso = false,
      bool force_asan_active = false,
      bool force_tsan_active = false,
      bool intel_pt = false);

  ~RecordSession() override;

  const DisableCPUIDFeatures& disable_cpuid_features() const {
    return disable_cpuid_features_;
  }
  bool use_syscall_buffer() const { return use_syscall_buffer_; }
  size_t syscall_buffer_size() const { return syscall_buffer_size_; }
  unsigned char syscallbuf_desched_sig() const { return syscallbuf_desched_sig_; }
  bool use_read_cloning() const { return use_read_cloning_; }
  bool use_file_cloning() const { return use_file_cloning_; }
  void set_ignore_sig(int sig) { ignore_sig = sig; }
  int get_ignore_sig() const { return ignore_sig; }
  void set_continue_through_sig(int sig) { continue_through_sig = sig; }
  int get_continue_through_sig() const { return continue_through_sig; }
  // Returns ranges to exclude from chaos mode memory allocation.
  // Used to exclude ranges used by sanitizers.
  const std::vector<MemoryRange> excluded_ranges() const {
    return excluded_ranges_;
  }
  MemoryRange fixed_global_exclusion_range() const {
    return fixed_global_exclusion_range_;
  }
  bool use_audit() const { return use_audit_; }
  bool unmap_vdso() { return unmap_vdso_; }
  uint64_t rr_signal_mask() const;

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
   * SIGKILL all tracees.
   */
  void terminate_tracees();

  /**
   * Close trace output without flushing syscall buffers or writing
   * task exit/termination records to the trace.
   */
  void close_trace_writer(TraceWriter::CloseStatus status);

  virtual RecordSession* as_record() override { return this; }

  TraceWriter& trace_writer() { return trace_out; }

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
    enable_chaos_ = enable_chaos;
    trace_out.set_chaos_mode(enable_chaos);
  }
  bool enable_chaos() const { return enable_chaos_; }

  void set_num_cores(int num_cores) {
    scheduler().set_num_cores(num_cores);
  }
  void set_use_read_cloning(bool enable) { use_read_cloning_ = enable; }
  void set_use_file_cloning(bool enable) { use_file_cloning_ = enable; }
  void set_syscall_buffer_size(size_t size) { syscall_buffer_size_ = size; }

  void set_wait_for_all(bool wait_for_all) {
    this->wait_for_all_ = wait_for_all;
  }

  virtual Task* new_task(pid_t tid, pid_t rec_tid, uint32_t serial,
                         SupportedArch a, const std::string& name) override;

  RecordTask* find_task(pid_t rec_tid) const;
  RecordTask* find_task(const TaskUid& tuid) const;
  RecordTask* find_detached_proxy_task(pid_t proxy_tid) const;

  void on_proxy_detach(RecordTask *t, pid_t new_tid);

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

  virtual TraceStream* trace_stream() override { return &trace_out; }

  /**
   * Send SIGTERM to all detached tasks and wait for them to finish.
   */
  void term_detached_tasks();

  /**
   * Forward SIGTERM to initial task
   */
  void forward_SIGTERM();

  void on_destroy_record_task(RecordTask* t);

private:
  RecordSession(const std::string& exe_path,
                const std::vector<std::string>& argv,
                const std::vector<std::string>& envp,
                const DisableCPUIDFeatures& features,
                SyscallBuffering syscallbuf,
                int syscallbuf_desched_sig,
                BindCPU bind_cpu,
                const TraceOutputPath& path_info,
                const TraceUuid* trace_id,
                bool use_audit,
                bool unmap_vdso,
                bool intel_pt);

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
  void handle_seccomp_trap(RecordTask* t, StepState* step_state,
                           uint16_t seccomp_data);
  void handle_seccomp_errno(RecordTask* t, StepState* step_state,
                            uint16_t seccomp_data);
  bool handle_ptrace_event(RecordTask** t_ptr, StepState* step_state,
                           RecordResult* result, bool* did_enter_syscall);
  bool handle_signal_event(RecordTask* t, StepState* step_state);
  void runnable_state_changed(RecordTask* t, StepState* step_state,
                              RecordResult* step_result,
                              bool can_consume_wait_status);
  bool signal_state_changed(RecordTask* t, StepState* step_state);
  void syscall_state_changed(RecordTask* t, StepState* step_state);
  void desched_state_changed(RecordTask* t);
  bool prepare_to_inject_signal(RecordTask* t, StepState* step_state);
  void task_continue(const StepState& step_state);

  TraceWriter trace_out;
  Scheduler scheduler_;
  ThreadGroup::shr_ptr initial_thread_group;
  SeccompFilterRewriter seccomp_filter_rewriter_;
  std::unique_ptr<const TraceUuid> trace_id;

  DisableCPUIDFeatures disable_cpuid_features_;
  int ignore_sig;
  int continue_through_sig;
  Switchable last_task_switchable;
  size_t syscall_buffer_size_;
  unsigned char syscallbuf_desched_sig_;
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

  std::vector<MemoryRange> excluded_ranges_;
  MemoryRange fixed_global_exclusion_range_;
  /**
   * Keeps track of detached tasks.
   */
  std::map<pid_t, RecordTask*> detached_task_map;

  bool use_audit_;
  bool unmap_vdso_;
};

} // namespace rr

#endif // RR_RECORD_SESSION_H_
