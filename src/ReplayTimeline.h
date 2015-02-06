/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_REPLAY_TIMELINE_H_
#define RR_REPLAY_TIMELINE_H_

#include <map>
#include <memory>
#include <vector>

#include "Registers.h"
#include "ReplaySession.h"
#include "TraceFrame.h"

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
  ReplayTimeline() {}
  ~ReplayTimeline();

  /**
   * A Mark references a precise point in time during the replay.
   * It may or may not have an associated ReplaySession checkpoint.
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

  private:
    friend class ReplayTimeline;

    Mark(std::weak_ptr<InternalMark> weak) : ptr(weak) {}

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
   * Ensure that the current session is explicitly checkpointed.
   * Explicit checkpoints are reference counted.
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

  // State-changing APIs. These may alter state associated with
  // current_session(). No breakpoints/watchpoints may be set when these
  // are called.

  /**
   * Reset the current session to the last available session before event
   * 'time'. Useful if you want to run up to that event.
   */
  void seek_to_before_event(TraceFrame::Time time) {
    assert_no_breakpoints_set();
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

private:
  /**
   * TraceFrame::Time + Ticks + ReplayStepKey does not uniquely identify
   * a program state, but they're intrinsically totally ordered.
   */
  struct MarkKey {
    MarkKey(TraceFrame::Time trace_time, Ticks ticks, ReplayStepKey step_key)
        : trace_time(trace_time), ticks(ticks), step_key(step_key) {}
    MarkKey(const MarkKey& other) = default;
    TraceFrame::Time trace_time;
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
    bool operator==(const MarkKey& other) const {
      return trace_time == other.trace_time && ticks == other.ticks &&
             step_key == other.step_key;
    }
    bool operator!=(const MarkKey& other) const { return !(*this == other); }
  };

  /**
   * MarkKey + Registers are assumed to identify a unique program state.
   * We can't order these states directly based on this data, so we have to
   * record the ordering in the ReplayTimeline.
   */
  struct InternalMark {
    InternalMark(ReplayTimeline* owner, Task* t, const MarkKey& key)
        : owner(owner), key(key), checkpoint_refcount(0) {
      if (t) {
        regs = t->regs();
      }
    }
    ~InternalMark();

    bool operator<(const std::shared_ptr<InternalMark> other);

    ReplayTimeline* owner;
    MarkKey key;
    Registers regs;
    ReplaySession::shr_ptr checkpoint;
    uint32_t checkpoint_refcount;
  };
  friend struct InternalMark;

  static MarkKey session_mark_key(const ReplaySession& session) {
    Task* t = session.current_task();
    return MarkKey(session.trace_reader().time(), t ? t->tick_count() : 0,
                   session.current_step_key());
  }
  MarkKey current_mark_key() const { return session_mark_key(*current); }
  // Returns a shared pointer to the mark if there is one for the current state.
  std::shared_ptr<InternalMark> current_mark();
  void remove_mark_with_checkpoint(const MarkKey& key);
  void seek_to_before_key(const MarkKey& key);
  void assert_no_breakpoints_set();

  // Reasonably fast since it just relies on checking the mark map.
  static bool less_than(const Mark& m1, const Mark& m2);

  // Run the session forward until we reach one of the given mark, or the
  // MarkKey increases. Returns the index of the mark we hit or marks.size()
  // if we didn't hit one.
  static size_t run_to_mark_or_tick(
      ReplaySession& session,
      const std::vector<std::weak_ptr<InternalMark> >& marks);

  ReplaySession::Flags session_flags;

  ReplaySession::shr_ptr current;

  /**
   * All known marks.
   *
   * An InternalMark appears in a ReplayTimeline 'marks' map if and only if
   * that ReplayTimeline is the InternalMark's 'owner'. InternalMark's
   * destructor removes it from its owner's 'marks' map. ReplayTimeline's
   * destructor clears the 'owner' of all marks in the map.
   *
   * For each MarkKey, the InternalMarks are stored in execution order.
   *
   * We assume there will only be a small number of InternalMarks per MarkKey.
   * This should be true because Task::tick_count() should increment
   * frequently during execution.
   */
  std::map<MarkKey, std::vector<std::weak_ptr<InternalMark> > > marks;

  /**
   * All mark keys with at least one checkpoint. The value is the number of
   * checkpoints. There can be multiple checkpoints for a given MarkKey
   * because a MarkKey may have multiple corresponding Marks.
   */
  std::map<MarkKey, uint32_t> marks_with_checkpoints;
};

#endif // RR_REPLAY_TIMELINE_H_
