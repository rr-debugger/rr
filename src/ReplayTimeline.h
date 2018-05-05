/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_REPLAY_TIMELINE_H_
#define RR_REPLAY_TIMELINE_H_

#include <iostream>
#include <map>
#include <memory>
#include <tuple>
#include <vector>

#include "BreakpointCondition.h"
#include "Registers.h"
#include "ReplaySession.h"
#include "ReplayTask.h"
#include "ReturnAddressList.h"
#include "TraceFrame.h"

namespace rr {

enum RunDirection { RUN_FORWARD, RUN_BACKWARD };

/**
 * This class manages a set of ReplaySessions corresponding to different points
 * in the same recording. It provides an API for explicitly managing
 * checkpoints along this timeline and navigating to specific events.
 */
class ReplayTimeline {
private:
  struct InternalMark;

public:
  ReplayTimeline(std::shared_ptr<ReplaySession> session,
                 const ReplaySession::Flags& session_flags);
  ReplayTimeline() : breakpoints_applied(false) {}
  ~ReplayTimeline();

  bool is_running() const { return current != nullptr; }

  /**
   * An estimate of how much progress a session has made. This should roughly
   * correlate to the time required to replay from the start of a session
   * to the current point, in microseconds.
   */
  typedef int64_t Progress;

  /**
   * A Mark references a precise point in time during the replay.
   * It can have an associated ReplaySession checkpoint.
   * It's mainly just a wrapper around InternalMark, but
   * InternalMark does not contain enough state to determine the
   * relative ordering of two Marks. So ReplayTimeline maintains
   * a database of Marks stored in time order to let us do such
   * comparisons.
   */
  class Mark {
  public:
    Mark() {}

    bool operator<(const Mark& other) const {
      return ReplayTimeline::less_than(*this, other);
    }
    bool operator>(const Mark& other) const { return other < *this; }
    bool operator<=(const Mark& other) const { return !(*this > other); }
    bool operator>=(const Mark& other) const { return !(*this < other); }
    bool operator==(const Mark& other) const { return ptr == other.ptr; }
    bool operator!=(const Mark& other) const { return !(*this == other); }
    operator bool() const { return ptr != nullptr; }

    /**
     * Return the values of the general-purpose registers at this mark.
     */
    const Registers& regs() const { return ptr->proto.regs; }
    const ExtraRegisters& extra_regs() const { return ptr->extra_regs; }

    FrameTime time() const { return ptr->proto.key.trace_time; }

  private:
    friend class ReplayTimeline;
    friend std::ostream& operator<<(std::ostream& s, const Mark& o);

    Mark(std::shared_ptr<InternalMark>& weak) { swap(ptr, weak); }

    std::shared_ptr<InternalMark> ptr;
  };

  /**
   * The current state. The current state can be moved forward or backward
   * using ReplaySession's APIs. Do not set breakpoints on its tasks directly.
   * Use ReplayTimeline's breakpoint methods.
   */
  ReplaySession& current_session() { return *current; }

  /**
   * Return a mark for the current state. A checkpoint need not be retained,
   * but this mark can be seeked to later.
   * This can be expensive in some (perhaps unusual) situations since we
   * may need to clone the current session and run it a bit, to figure out
   * where we are relative to other Marks. So don't call this unless you
   * need it.
   */
  Mark mark();

  /**
   * Indicates that the current replay position is the result of
   * singlestepping from 'from'.
   */
  void mark_after_singlestep(const Mark& from, const ReplayResult& result);

  /**
   * Returns true if it's safe to add a checkpoint here.
   */
  bool can_add_checkpoint() { return current->can_clone(); }

  /**
   * Ensure that the current session is explicitly checkpointed.
   * Explicit checkpoints are reference counted.
   * Only call this if can_add_checkpoint would return true.
   */
  Mark add_explicit_checkpoint();

  /**
   * Remove an explicit checkpoint reference count for this mark.
   */
  void remove_explicit_checkpoint(const Mark& mark);

  /**
   * Return true if we're currently at the given mark.
   */
  bool at_mark(const Mark& mark) { return current_mark() == mark.ptr; }

  // Add/remove breakpoints and watchpoints. Use these APIs instead
  // of operating on the task directly, so that ReplayTimeline can track
  // breakpoints and automatically move them across sessions as necessary.
  // Only one breakpoint for a given address space/addr combination can be set;
  // setting another for the same address space/addr will replace the first.
  // Likewise only one watchpoint for a given task/addr/num_bytes/type can be
  // set. gdb expects that setting two breakpoints on the same address and then
  // removing one removes both.
  bool add_breakpoint(ReplayTask* t, remote_code_ptr addr,
                      std::unique_ptr<BreakpointCondition> condition = nullptr);
  // You can't remove a breakpoint with a specific condition, so don't
  // place multiple breakpoints with conditions on the same location.
  void remove_breakpoint(ReplayTask* t, remote_code_ptr addr);
  bool add_watchpoint(ReplayTask* t, remote_ptr<void> addr, size_t num_bytes,
                      WatchType type,
                      std::unique_ptr<BreakpointCondition> condition = nullptr);
  // You can't remove a watchpoint with a specific condition, so don't
  // place multiple breakpoints with conditions on the same location.
  void remove_watchpoint(ReplayTask* t, remote_ptr<void> addr, size_t num_bytes,
                         WatchType type);
  void remove_breakpoints_and_watchpoints();
  bool has_breakpoint_at_address(ReplayTask* t, remote_code_ptr addr);
  bool has_watchpoint_at_address(ReplayTask* t, remote_ptr<void> addr,
                                 size_t num_bytes, WatchType type);

  /**
   * Ensure that reverse execution never proceeds into an event before
   * |event|. Reverse execution will stop with a |task_exit| break status when
   * at the beginning of this event.
   */
  void set_reverse_execution_barrier_event(FrameTime event) {
    reverse_execution_barrier_event = event;
  }

  // State-changing APIs. These may alter state associated with
  // current_session().

  /**
   * Reset the current session to the last available session before event
   * 'time'. Useful if you want to run up to that event.
   */
  void seek_to_before_event(FrameTime time) {
    return seek_to_before_key(MarkKey(time, 0, ReplayStepKey()));
  }

  /**
   * Reset the current session to the last checkpointed session before (or at)
   * the mark. Will return at the mark if this mark was explicitly checkpointed
   * previously (and not deleted).
   */
  void seek_up_to_mark(const Mark& mark);

  /**
   * Sets current session to 'mark' by restoring the nearest useful checkpoint
   * and executing forwards if necessary.
   */
  void seek_to_mark(const Mark& mark);

  /**
   * Replay 'current'.
   * If there is a breakpoint at the current task's current ip(), then
   * when running forward we will immediately break at the breakpoint. When
   * running backward we will ignore the initial "hit" of the breakpoint ---
   * this is the behavior gdb expects.
   * Likewise, if there is a breakpoint at the current task's current ip(),
   * then running forward will immediately break at the breakpoint, but
   * running backward will ignore the initial "hit" of the breakpoint; this is
   * what gdb expects.
   *
   * replay_step_forward only does one replay step. That means we'll only
   * execute code in current_session().current_task().
   */
  ReplayResult replay_step_forward(RunCommand command, FrameTime stop_at_time);

  ReplayResult reverse_continue(
      const std::function<bool(ReplayTask* t)>& stop_filter,
      const std::function<bool()>& interrupt_check);
  ReplayResult reverse_singlestep(
      const TaskUid& tuid, Ticks tuid_ticks,
      const std::function<bool(ReplayTask* t)>& stop_filter,
      const std::function<bool()>& interrupt_check);

  /**
   * Try to identify an existing Mark which is known to be one singlestep
   * before 'from', and for which we know singlestepping to 'from' would
   * trigger no break statuses other than "singlestep_complete".
   * If we can't, return a null Mark.
   * Will only return a Mark for the same executing task as 'from', which
   * must be 't'.
   */
  Mark lazy_reverse_singlestep(const Mark& from, ReplayTask* t);

  /**
   * Different strategies for placing automatic checkpoints.
   */
  enum CheckpointStrategy {
    /**
     * Use this when we want to bound the overhead of checkpointing to be
     * insignificant relative to the cost of forward execution.
     */
    LOW_OVERHEAD,
    /**
     * Use this when we expect reverse execution to happen soon, to a
     * destination not far behind the current execution point. In this case
     * it's worth increasing checkpoint density.
     * We pass this when we have opportunities to make checkpoints during
     * reverse_continue or reverse_singlestep, since it's common for short
     * reverse-executions to follow other reverse-execution.
     */
    EXPECT_SHORT_REVERSE_EXECUTION
  };

  /**
   * We track the set of breakpoints/watchpoints requested by the client.
   * When we switch to a new ReplaySession, these need to be reapplied before
   * replaying that session, but we do this lazily.
   * apply_breakpoints_and_watchpoints() forces the breakpoints/watchpoints
   * to be applied to the current session.
   * Our checkpoints never have breakpoints applied.
   */
  void apply_breakpoints_and_watchpoints();

private:
  /**
   * A MarkKey consists of FrameTime + Ticks + ReplayStepKey. These values
   * do not uniquely identify a program state, but they are intrinsically
   * totally ordered. The ReplayTimeline::marks database is an ordered
   * map from MarkKeys to a time-ordered list of Marks associated with each
   * MarkKey.
   */
  struct MarkKey {
    MarkKey(FrameTime trace_time, Ticks ticks, ReplayStepKey step_key)
        : trace_time(trace_time), ticks(ticks), step_key(step_key) {}
    MarkKey(const MarkKey& other) = default;
    FrameTime trace_time;
    Ticks ticks;
    ReplayStepKey step_key;
    bool operator<(const MarkKey& other) const {
      if (trace_time < other.trace_time) {
        return true;
      }
      if (trace_time > other.trace_time) {
        return false;
      }
      if (ticks < other.ticks) {
        return true;
      }
      if (ticks > other.ticks) {
        return false;
      }
      return step_key < other.step_key;
    }
    bool operator<=(const MarkKey& other) const { return !(other < *this); }
    bool operator>(const MarkKey& other) const { return other < *this; }
    bool operator>=(const MarkKey& other) const { return !(*this < other); }
    bool operator==(const MarkKey& other) const {
      return trace_time == other.trace_time && ticks == other.ticks &&
             step_key == other.step_key;
    }
    bool operator!=(const MarkKey& other) const { return !(*this == other); }
  };
  friend std::ostream& operator<<(std::ostream& s, const MarkKey& o);

  /**
   * All the information we'll need to construct a mark lazily.
   * Marks are expensive to create since we may have to restore
   * a previous session state so we can replay forward to find out
   * how the Mark should be ordered relative to other Marks with the same
   * MarkKey. So instead of creating a Mark for the current moment
   * whenever we *might* need to return to that moment, create a ProtoMark
   * instead. This contains a snapshot of enough state to create a full
   * Mark later.
   * MarkKey + Registers + ReturnAddressList are assumed to identify a unique
   * program state.
   */
  struct ProtoMark {
    ProtoMark(const MarkKey& key, ReplayTask* t)
        : key(key), regs(t->regs()), return_addresses(ReturnAddressList(t)) {}
    ProtoMark(const MarkKey& key) : key(key) {}

    bool equal_states(ReplaySession& session) const;

    MarkKey key;
    Registers regs;
    ReturnAddressList return_addresses;
  };

  /**
   * Everything we know about the tracee state for a particular Mark.
   * This data alone does not allow us to determine the time ordering
   * of two Marks.
   */
  struct InternalMark {
    InternalMark(ReplayTimeline* owner, ReplaySession& session,
                 const MarkKey& key)
        : owner(owner),
          proto(key),
          ticks_at_event_start(session.ticks_at_start_of_current_event()),
          checkpoint_refcount(0),
          singlestep_to_next_mark_no_signal(false) {
      ReplayTask* t = session.current_task();
      if (t) {
        proto = ProtoMark(key, t);
        extra_regs = t->extra_regs();
      }
    }
    ~InternalMark();

    bool operator<(const std::shared_ptr<InternalMark> other);

    bool equal_states(ReplaySession& session) const;

    ReplayTimeline* owner;
    // Reuse ProtoMark to contain the MarkKey + Registers + ReturnAddressList.
    ProtoMark proto;
    ExtraRegisters extra_regs;
    // Optional checkpoint for this Mark.
    ReplaySession::shr_ptr checkpoint;
    Ticks ticks_at_event_start;
    // Number of users of `checkpoint`.
    uint32_t checkpoint_refcount;
    // The next InternalMark in the ReplayTimeline's Mark vector is the result
    // of singlestepping from this mark *and* no signal is reported in the
    // break_status when doing such a singlestep.
    bool singlestep_to_next_mark_no_signal;
  };
  friend struct InternalMark;
  friend std::ostream& operator<<(std::ostream& s, const InternalMark& o);
  friend std::ostream& operator<<(std::ostream& s, const ProtoMark& o);

  /**
   * unapply_breakpoints_and_watchpoints() forces the breakpoints/watchpoints
   * to not be applied to the current session. Use this when we need to
   * clone the current session or replay the current session without
   * triggering breakpoints.
   */
  void unapply_breakpoints_and_watchpoints();

  void apply_breakpoints_internal();
  void unapply_breakpoints_internal();

  static MarkKey session_mark_key(ReplaySession& session) {
    ReplayTask* t = session.current_task();
    return MarkKey(session.trace_reader().time(), t ? t->tick_count() : 0,
                   session.current_step_key());
  }
  MarkKey current_mark_key() const { return session_mark_key(*current); }

  ProtoMark proto_mark() const;
  void seek_to_proto_mark(const ProtoMark& pmark);

  // Returns a shared pointer to the mark if there is one for the current state.
  std::shared_ptr<InternalMark> current_mark();
  void remove_mark_with_checkpoint(const MarkKey& key);
  void seek_to_before_key(const MarkKey& key);
  enum ForceProgress { FORCE_PROGRESS, DONT_FORCE_PROGRESS };
  // Run forward towards the midpoint of the current position and |end|.
  // Must stop before we reach |end|.
  // Returns false if we made no progress.
  bool run_forward_to_intermediate_point(const Mark& end, ForceProgress force);
  struct ReplayStepToMarkStrategy {
    ReplayStepToMarkStrategy() : singlesteps_to_perform(0) {}
    ReplaySession::StepConstraints setup_step_constraints();
    uint32_t singlesteps_to_perform;
  };
  void update_strategy_and_fix_watchpoint_quirk(
      ReplayStepToMarkStrategy& strategy,
      const ReplaySession::StepConstraints& constraints, ReplayResult& result,
      const ProtoMark& before);
  // Take a single replay step towards |mark|. Stop before or at |mark|, and
  // stop if any breakpoint/watchpoint/signal is hit.
  // Maintain current strategy state in |strategy|. Passing the same
  // |strategy| object to consecutive replay_step_to_mark invocations helps
  // optimize performance.
  ReplayResult replay_step_to_mark(const Mark& mark,
                                   ReplayStepToMarkStrategy& strategy);
  ReplayResult singlestep_with_breakpoints_disabled();
  bool fix_watchpoint_coalescing_quirk(ReplayResult& result,
                                       const ProtoMark& before);
  Mark find_singlestep_before(const Mark& mark);
  bool is_start_of_reverse_execution_barrier_event();

  void update_observable_break_status(ReplayTimeline::Mark& now,
                                      const ReplayResult& result);
  ReplayResult reverse_singlestep(
      const Mark& origin, const TaskUid& step_tuid, Ticks step_ticks,
      const std::function<bool(ReplayTask* t)>& stop_filter,
      const std::function<bool()>& interrupt_check);

  // Reasonably fast since it just relies on checking the mark map.
  static bool less_than(const Mark& m1, const Mark& m2);

  Progress estimate_progress();

  /**
   * Called when the current session has moved forward to a new execution
   * point and we might want to make a checkpoint to support reverse-execution.
   * If this adds a checkpoint, it will call
   * discard_past_reverse_exec_checkpoints
   * first.
   */
  void maybe_add_reverse_exec_checkpoint(CheckpointStrategy strategy);
  /**
   * Discard some reverse-exec checkpoints in the past, if necessary. We do
   * this to stop the number of checkpoints growing out of control.
   */
  void discard_past_reverse_exec_checkpoints(CheckpointStrategy strategy);
  /**
   * Discard all reverse-exec checkpoints that are in the future (they're
   * useless).
   */
  void discard_future_reverse_exec_checkpoints();

  Mark set_short_checkpoint();

  /**
   * If result.break_status hit watchpoints or breakpoints, evaluate their
   * conditions and clear the break_status flags if the conditions don't hold.
   */
  void evaluate_conditions(ReplayResult& result);

  ReplaySession::Flags session_flags;

  ReplaySession::shr_ptr current;
  // current is known to be at or after this mark
  std::shared_ptr<InternalMark> current_at_or_after_mark;

  /**
   * All known marks.
   *
   * An InternalMark appears in a ReplayTimeline 'marks' map if and only if
   * that ReplayTimeline is the InternalMark's 'owner'. ReplayTimeline's
   * destructor clears the 'owner' of all marks in the map.
   *
   * For each MarkKey, the InternalMarks are stored in execution order.
   *
   * The key problem we're dealing with here is that we don't have any state
   * that we can use to compute a total time order on Marks. MarkKeys are
   * totally ordered, but different program states can have the same MarkKey
   * (i.e. same retired conditional branch count). The only way to determine
   * the time ordering of two Marks m1 and m2 is to actually replay the
   * execution until we see m1 and m2 and observe which one happened first.
   * We record that ordering for all Marks by storing all the Marks for a given
   * MarkKey in vector ordered by time.
   * Determining this order is expensive so we avoid creating Marks unless we
   * really need to! If we're at a specific point in time and we *may* need to
   * create a Mark for this point later, create a ProtoMark instead to
   * capture enough state so that a Mark can later be created if needed.
   *
   * We assume there will be a limited number of InternalMarks per MarkKey.
   * This should be true because ReplayTask::tick_count() should increment
   * frequently during execution. In some cases we see hundreds of elements
   * but that's not too bad.
   */
  std::map<MarkKey, std::vector<std::shared_ptr<InternalMark>>> marks;

  /**
   * All mark keys with at least one checkpoint. The value is the number of
   * checkpoints. There can be multiple checkpoints for a given MarkKey
   * because a MarkKey may have multiple corresponding Marks.
   */
  std::map<MarkKey, uint32_t> marks_with_checkpoints;

  std::set<std::tuple<AddressSpaceUid, remote_code_ptr,
                      std::unique_ptr<BreakpointCondition>>>
      breakpoints;
  std::set<std::tuple<AddressSpaceUid, remote_ptr<void>, size_t, WatchType,
                      std::unique_ptr<BreakpointCondition>>>
      watchpoints;
  bool breakpoints_applied;

  FrameTime reverse_execution_barrier_event;

  /**
   * Checkpoints used to accelerate reverse execution.
   */
  std::map<Mark, Progress> reverse_exec_checkpoints;

  /**
   * When these are non-null, then when singlestepping from
   * no_break_interval_start to no_break_interval_end, none of the currently
   * set watchpoints fire.
   */
  Mark no_watchpoints_hit_interval_start;
  Mark no_watchpoints_hit_interval_end;

  /**
   * A single checkpoint that's very close to the current point, used to
   * accelerate a sequence of reverse singlestep operations.
   */
  Mark reverse_exec_short_checkpoint;
};

std::ostream& operator<<(std::ostream& s, const ReplayTimeline::Mark& o);

} // namespace rr

#endif // RR_REPLAY_TIMELINE_H_
