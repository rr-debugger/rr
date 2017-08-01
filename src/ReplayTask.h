/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_REPLAY_TASK_H_
#define RR_REPLAY_TASK_H_

#include "Task.h"

namespace rr {

class TraceFrame;

/**
 * Every Task owned by a ReplaySession is a ReplayTask. Functionality that
 * only applies during replay belongs here.
 */
class ReplayTask : public Task {
public:
  ReplayTask(ReplaySession& session, pid_t _tid, pid_t _rec_tid,
             uint32_t serial, SupportedArch a);

  ReplaySession& session() const;
  TraceReader& trace_reader() const;

  /**
   * Initialize tracee buffers in this, i.e., implement
   * RRCALL_init_syscall_buffer.  This task must be at the point
   * of *exit from* the rrcall.  Registers will be updated with
   * the return value from the rrcall, which is also returned
   * from this call.  |map_hint| suggests where to map the
   * region; see |init_syscallbuf_buffer()|.
   */
  void init_buffers(remote_ptr<void> map_hint);
  /**
   * Call this method when the exec has completed.
   */
  void post_exec_syscall(const std::string& replay_exe);

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
  const TraceFrame& current_trace_frame();
  FrameTime current_frame_time();
  /** Restore the next chunk of saved data from the trace to this. */
  ssize_t set_data_from_trace();
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

private:
  template <typename Arch> void init_buffers_arch(remote_ptr<void> map_hint);

  ~ReplayTask() {}
};

} // namespace rr

#endif /* RR_REPLAY_TASK_H_ */
