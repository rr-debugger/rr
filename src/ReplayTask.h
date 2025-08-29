/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_REPLAY_TASK_H_
#define RR_REPLAY_TASK_H_

#include "AutoRemoteSyscalls.h"
#include "Task.h"

namespace rr {

class TraceFrame;

/**
 * Every Task owned by a ReplaySession is a ReplayTask. Functionality that
 * only applies during replay belongs here.
 */
class ReplayTask final : public Task {
public:
  ReplayTask(ReplaySession& session, pid_t _tid, pid_t _rec_tid,
             uint32_t serial, SupportedArch a,
             const std::string& name);

  ReplaySession& session() const;
  TraceReader& trace_reader() const;

  /**
   * Initialize tracee buffers in this, i.e., implement
   * RRCALL_init_syscall_buffer.  This task must be at the point
   * of *exit from* the rrcall.  Registers will be updated with
   * the return value from the rrcall, which is also returned
   * from this call..
   */
  void init_buffers();
  /**
   * Call this method when the exec has completed.
   * `replay_exe` is the name of the real executable file in the trace if we have one,
   * otherwise the name of the original executable file. This gets passed to gdb
   * as a best-effort to give gdb a file to look at.
   * `original_replay_exe` is the name of the original executable file.
   */
  void post_exec_syscall(const std::string& replay_exe, const std::string& original_replay_exe);

  void set_name(AutoRemoteSyscalls& remote, const std::string& name) override;

  void did_prctl_set_prname(remote_ptr<void> child_addr) override;

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
  const TraceFrame& current_trace_frame() const;
  FrameTime current_frame_time() const;

  /** Restore the next chunk of this frame's saved data from the trace to this. */
  void apply_data_record_from_trace();
  /** Restore all remaining chunks of saved data for the current trace frame. */
  void apply_all_data_records_from_trace();

  /**
   * Set the syscall-return-value register of this to what was
   * saved in the current trace frame.
   */
  void set_return_value_from_trace();

  /**
   * Used when an execve changes the tid of a non-main-thread to the
   * thread-group leader.
   */
  void set_real_tid_and_update_serial(pid_t tid);

  /** Return the extra registers of this. Asserts if the task died. */
  const ExtraRegisters& extra_regs();

  void note_sched_in_syscallbuf_syscall_hook() {
    seen_sched_in_syscallbuf_syscall_hook = true;
  }

  std::string name() const override {
    return name_;
  }

private:
  template <typename Arch> void init_buffers_arch();

  bool post_vm_clone(CloneReason reason, int flags, Task* origin) override;

  std::string name_;

  // Set to true when we see a sched event with in_syscallbuf_syscall_hook set.
  bool seen_sched_in_syscallbuf_syscall_hook;
};

} // namespace rr

#endif /* RR_REPLAY_TASK_H_ */
