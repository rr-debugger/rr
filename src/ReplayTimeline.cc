/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

//#define DEBUGTAG "ReplayTimeline"

#include "ReplayTimeline.h"

#include "log.h"

using namespace rr;
using namespace std;

ReplayTimeline::InternalMark::~InternalMark() {
  if (owner && checkpoint) {
    owner->remove_mark_with_checkpoint(key);
  }
}

ostream& operator<<(ostream& s, const ReplayTimeline::MarkKey& o) {
  return s << "time:" << o.trace_time << ",ticks:" << o.ticks
           << ",st:" << o.step_key.as_int();
}

ostream& operator<<(ostream& s, const ReplayTimeline::InternalMark& o) {
  return s << "{" << o.key << ",regs_ip:" << HEX(o.regs.ip().as_int()) << "}";
}

ostream& operator<<(ostream& s, const ReplayTimeline::Mark& o) {
  if (!o.ptr) {
    return s << "{null}";
  }
  return s << *o.ptr.get();
}

bool ReplayTimeline::less_than(const Mark& m1, const Mark& m2) {
  assert(m1.ptr->owner == m2.ptr->owner);
  if (m1.ptr->key < m2.ptr->key) {
    return true;
  }
  if (m2.ptr->key < m1.ptr->key) {
    return false;
  }
  if (!m1.ptr->owner) {
    return false;
  }
  for (shared_ptr<InternalMark>& m : m1.ptr->owner->marks[m1.ptr->key]) {
    if (m == m2.ptr) {
      return false;
    }
    if (m == m1.ptr) {
      return true;
    }
  }
  assert(0 && "Marks missing from vector, invariants broken!");
  return false;
}

ReplayTimeline::ReplayTimeline(std::shared_ptr<ReplaySession> session,
                               const ReplaySession::Flags& session_flags)
    : session_flags(session_flags),
      current(std::move(session)),
      breakpoints_applied(false) {
  current->set_visible_execution(false);
  current->set_flags(session_flags);
}

ReplayTimeline::~ReplayTimeline() {
  for (auto it : marks) {
    for (shared_ptr<InternalMark>& itv : it.second) {
      itv->owner = nullptr;
    }
  }
}

static bool equal_regs(const Registers& r1, const Registers& r2) {
  // Compare ip()s first since they will usually fail to match, especially
  // when we're comparing InternalMarks with the same MarkKey
  return r1.ip() == r2.ip() && r1.matches(r2);
}

shared_ptr<ReplayTimeline::InternalMark> ReplayTimeline::current_mark() {
  Task* t = current->current_task();
  auto it = marks.find(current_mark_key());
  // Avoid creating an entry in 'marks' if it doesn't already exist
  if (it != marks.end()) {
    for (shared_ptr<InternalMark>& m : it->second) {
      if (equal_regs(m->regs, t->regs())) {
        return m;
      }
    }
  }
  return shared_ptr<InternalMark>();
}

ReplayTimeline::Mark ReplayTimeline::mark() {
  Mark result;
  auto cm = current_mark();
  if (cm) {
    swap(cm, result.ptr);
    return result;
  }

  MarkKey key = current_mark_key();
  Task* t = current->current_task();
  shared_ptr<InternalMark> m = make_shared<InternalMark>(this, t, key);

  auto& mark_vector = marks[key];
  if (mark_vector.empty()) {
    mark_vector.push_back(m);
  } else if (mark_vector[mark_vector.size() - 1] == current_at_or_after_mark) {
    mark_vector.push_back(m);
  } else {
    // Now the hard part: figuring out where to put it in the list of existing
    // marks.
    unapply_breakpoints_and_watchpoints();
    ReplaySession::shr_ptr tmp_session = current->clone();
    vector<shared_ptr<InternalMark> >::iterator mark_index = mark_vector.end();

    // We could set breakpoints at the marks and then continue with an
    // interrupt set to fire when our tick-count increases. But that requires
    // new replay functionality (probably a new RunCommand), so for now, do the
    // simplest thing and just single-step until the MarkKey has increased.
    vector<shared_ptr<InternalMark> > new_marks;
    new_marks.push_back(m);
    while (true) {
      auto result = tmp_session->replay_step(RUN_SINGLESTEP);
      if (session_mark_key(*tmp_session) != key ||
          result.status != REPLAY_CONTINUE) {
        break;
      }
      if (result.break_status.reason != BREAK_SINGLESTEP) {
        continue;
      }

      Task* t = tmp_session->current_task();
      for (auto it = mark_vector.begin(); it != mark_vector.end(); ++it) {
        shared_ptr<InternalMark>& existing_mark = *it;
        if (equal_regs(existing_mark->regs, t->regs())) {
          mark_index = it;
          break;
        }
      }
      if (mark_index != mark_vector.end()) {
        break;
      }

      // Some callers singlestep through N instructions, all with the same
      // MarkKey, requesting a Mark after each step. If there's a Mark at the
      // end of the N instructions, this could mean N(N+1)/2 singlestep
      // operations total. To avoid that, add all the intermediate states to
      // the mark map now, so the first mark() call will perform N singlesteps
      // and the rest will perform none.
      new_marks.push_back(make_shared<InternalMark>(this, t, key));
    }

    // mark_index is the current index of the next mark after 'current'. So
    // insert our new marks at mark_index.
    mark_vector.insert(mark_index, new_marks.begin(), new_marks.end());
  }
  swap(m, result.ptr);
  current_at_or_after_mark = result.ptr;
  return result;
}

ReplayTimeline::Mark ReplayTimeline::add_explicit_checkpoint() {
  Mark m = mark();
  if (!m.ptr->checkpoint) {
    unapply_breakpoints_and_watchpoints();
    m.ptr->checkpoint = current->clone();
    auto key = m.ptr->key;
    if (marks_with_checkpoints.find(key) == marks_with_checkpoints.end()) {
      marks_with_checkpoints[key] = 1;
    } else {
      marks_with_checkpoints[key]++;
    }
  }
  ++m.ptr->checkpoint_refcount;
  return m;
}

void ReplayTimeline::remove_mark_with_checkpoint(const MarkKey& key) {
  assert(marks_with_checkpoints[key] > 0);
  if (--marks_with_checkpoints[key] == 0) {
    marks_with_checkpoints.erase(key);
  }
}

void ReplayTimeline::remove_explicit_checkpoint(const Mark& mark) {
  assert(mark.ptr->checkpoint_refcount > 0);
  if (--mark.ptr->checkpoint_refcount == 0) {
    mark.ptr->checkpoint = nullptr;
    remove_mark_with_checkpoint(mark.ptr->key);
  }
}

void ReplayTimeline::seek_to_before_key(const MarkKey& key) {
  auto it = marks_with_checkpoints.lower_bound(key);
  // 'it' points to the first value equivalent to or greater than 'key'.
  auto current_key = current_mark_key();
  if (it == marks_with_checkpoints.begin()) {
    if (current_key < key) {
      // We can use the current session, so do nothing.
    } else {
      // nowhere earlier to go, so restart from beginning.
      current = ReplaySession::create(current->trace_reader().dir());
      breakpoints_applied = false;
      current_at_or_after_mark = nullptr;
      current->set_flags(session_flags);
    }
  } else {
    --it;
    // 'it' is now at the last checkpoint before 'key'
    if (it->first < current_key && current_key < key) {
      // Current state is closer to the destination than any checkpoint we
      // have, so do nothing.
    } else {
      // Return one of the checkpoints at *it.
      current = nullptr;
      for (auto mark_it : marks[it->first]) {
        shared_ptr<InternalMark> m(mark_it);
        if (m->checkpoint) {
          current = m->checkpoint->clone();
          break;
        }
      }
      assert(current);
      breakpoints_applied = false;
      current_at_or_after_mark = nullptr;
    }
  }
}

void ReplayTimeline::seek_up_to_mark(const Mark& mark) {
  if (current_mark_key() == mark.ptr->key) {
    Mark cm = this->mark();
    if (cm <= mark) {
      // close enough, stay where we are
      return;
    }

    // Check if any of the marks with the same key as 'mark', but before 'mark',
    // are usable.
    for (shared_ptr<InternalMark>& m : marks[mark.ptr->key]) {
      if (m->checkpoint) {
        current = m->checkpoint->clone();
        breakpoints_applied = false;
        current_at_or_after_mark = nullptr;
        return;
      }
      if (m == mark.ptr) {
        break;
      }
    }
  }

  return seek_to_before_key(mark.ptr->key);
}

static void clear_break_status_reason(BreakStatus& break_status,
                                      BreakReason reason) {
  if (break_status.reason == reason) {
    break_status.reason =
        break_status.watch_address.is_null() ? BREAK_NONE : BREAK_WATCHPOINT;
  }
}

ReplayResult ReplayTimeline::replay_step_to_mark(const Mark& mark) {
  ReplayResult result;
  if (current->trace_reader().time() < mark.ptr->key.trace_time) {
    result = current->replay_step(RUN_CONTINUE, mark.ptr->key.trace_time);
  } else {
    Task* t = current->current_task();
    remote_ptr<uint8_t> mark_addr = mark.ptr->regs.ip();
    if (t->regs().ip() == mark_addr &&
        current->current_step_key().in_execution()) {
      // At required IP, but not in the correct state. Singlestep over
      // this IP.
      result = current->replay_step(RUN_SINGLESTEP);
      // Hide internal singlestep
      clear_break_status_reason(result.break_status, BREAK_SINGLESTEP);
    } else {
      // Get a shared reference to t->vm() in case t dies during replay_step
      shared_ptr<AddressSpace> vm = t->vm();
      vm->add_breakpoint(mark_addr, TRAP_BKPT_USER);
      result = current->replay_step(RUN_CONTINUE);
      vm->remove_breakpoint(mark_addr, TRAP_BKPT_USER);
      // If our breakpoint is the only breakpoint there, and we hit it,
      // pretend we didn't so the caller doesn't get confused with its own
      // breakpoints.
      pair<AddressSpaceUid, remote_ptr<uint8_t> > p(vm->uid(), mark_addr);
      if (t->regs().ip() == mark_addr && breakpoints.count(p) == 0) {
        clear_break_status_reason(result.break_status, BREAK_BREAKPOINT);
      }
    }
  }
  return result;
}

void ReplayTimeline::seek_to_mark(const Mark& mark) {
  seek_up_to_mark(mark);
  while (current_mark() != mark.ptr) {
    unapply_breakpoints_and_watchpoints();
    replay_step_to_mark(mark);
  }
  current_at_or_after_mark = mark.ptr;
  // XXX handle cases where breakpoints can't yet be applied
}

bool ReplayTimeline::add_breakpoint(Task* t, remote_ptr<uint8_t> addr) {
  // Apply breakpoints now; we need to actually try adding this breakpoint
  // to see if it works.
  apply_breakpoints_and_watchpoints();
  if (!t->vm()->add_breakpoint(addr, TRAP_BKPT_USER)) {
    return false;
  }
  breakpoints.insert(make_pair(t->vm()->uid(), addr));
  return true;
}

void ReplayTimeline::remove_breakpoint(Task* t, remote_ptr<uint8_t> addr) {
  if (breakpoints_applied) {
    t->vm()->remove_breakpoint(addr, TRAP_BKPT_USER);
  }
  auto it = breakpoints.find(make_pair(t->vm()->uid(), addr));
  ASSERT(t, it != breakpoints.end());
  breakpoints.erase(it);
}

bool ReplayTimeline::has_breakpoint_at_address(Task* t,
                                               remote_ptr<uint8_t> addr) {
  return breakpoints.find(make_pair(t->vm()->uid(), addr)) != breakpoints.end();
}

bool ReplayTimeline::add_watchpoint(Task* t, remote_ptr<void> addr,
                                    size_t num_bytes, WatchType type) {
  // Apply breakpoints now; we need to actually try adding this breakpoint
  // to see if it works.
  apply_breakpoints_and_watchpoints();
  if (!t->vm()->add_watchpoint(addr, num_bytes, type)) {
    return false;
  }
  watchpoints.insert(make_tuple(t->vm()->uid(), addr, num_bytes, type));
  return true;
}

void ReplayTimeline::remove_watchpoint(Task* t, remote_ptr<void> addr,
                                       size_t num_bytes, WatchType type) {
  if (breakpoints_applied) {
    t->vm()->remove_watchpoint(addr, num_bytes, type);
  }
  auto it = watchpoints.find(make_tuple(t->vm()->uid(), addr, num_bytes, type));
  ASSERT(t, it != watchpoints.end());
  watchpoints.erase(it);
}

void ReplayTimeline::remove_breakpoints_and_watchpoints() {
  unapply_breakpoints_and_watchpoints();
  breakpoints.clear();
  watchpoints.clear();
}

void ReplayTimeline::apply_breakpoints_and_watchpoints() {
  if (breakpoints_applied) {
    return;
  }
  breakpoints_applied = true;
  for (auto& bp : breakpoints) {
    AddressSpace* vm = current->find_address_space(bp.first);
    // XXX handle cases where we can't apply a breakpoint right now. Later
    // during replay the address space might be created (or new mappings might
    // be created) and we should reapply breakpoints then.
    if (vm) {
      vm->add_breakpoint(bp.second, TRAP_BKPT_USER);
    }
  }
  for (auto& wp : watchpoints) {
    AddressSpace* vm = current->find_address_space(get<0>(wp));
    // XXX handle cases where we can't apply a watchpoint right now. Later
    // during replay the address space might be created (or new mappings might
    // be created) and we should reapply watchpoints then.
    // XXX we could make this more efficient by providing a method to set
    // several watchpoints at once on a given AddressSpace.
    if (vm) {
      vm->add_watchpoint(get<1>(wp), get<2>(wp), get<3>(wp));
    }
  }
}

void ReplayTimeline::unapply_breakpoints_and_watchpoints() {
  if (!breakpoints_applied) {
    return;
  }
  breakpoints_applied = false;
  for (auto& vm : current->vms()) {
    vm->remove_all_breakpoints();
    vm->remove_all_watchpoints();
  }
}

ReplayResult ReplayTimeline::singlestep_with_breakpoints_disabled() {
  apply_breakpoints_and_watchpoints();
  for (auto& vm : current->vms()) {
    vm->remove_all_breakpoints();
  }
  auto result = current->replay_step(RUN_SINGLESTEP);
  for (auto& bp : breakpoints) {
    AddressSpace* vm = current->find_address_space(bp.first);
    if (vm) {
      vm->add_breakpoint(bp.second, TRAP_BKPT_USER);
    }
  }
  return result;
}

ReplayResult ReplayTimeline::reverse_continue() {
  ReplayResult result;
  Mark end = mark();
  LOG(debug) << "ReplayTimeline::reverse_continue from " << end;

  while (true) {
    seek_to_before_key(end.ptr->key);
    if (current_mark_key() == end.ptr->key) {
      LOG(debug) << "Couldn't seek to before " << end << ", returning exit";
      // Can't go backwards. Call this an exit.
      result.status = REPLAY_EXITED;
      result.break_status.reason = BREAK_NONE;
      return result;
    }
    Mark start = mark();
    LOG(debug) << "Seeked backward from " << end << " to " << start;
    bool at_breakpoint = false;
    bool last_stop_is_watch_or_signal = false;
    Mark dest;
    ReplayResult final_result;
    TaskUid final_tuid;
    while (true) {
      apply_breakpoints_and_watchpoints();
      if (at_breakpoint) {
        result = singlestep_with_breakpoints_disabled();
      } else {
        result = replay_step_to_mark(end);
      }
      if (!result.break_status.watch_address.is_null() ||
          result.break_status.reason == BREAK_SIGNAL) {
        assert(result.break_status.reason != BREAK_NONE);
        dest = mark();
        LOG(debug) << "Found watch/signal break at " << dest;
        final_result = result;
        final_tuid = result.break_status.task ? result.break_status.task->tuid()
                                              : TaskUid();
        last_stop_is_watch_or_signal = true;
      }
      if (at_mark(end)) {
        break;
      }
      assert(result.status == REPLAY_CONTINUE);
      // If there is a breakpoint at the current ip() where we start a
      // reverse-continue, gdb expects us to skip it.
      if (result.break_status.reason == BREAK_BREAKPOINT) {
        assert(result.break_status.watch_address.is_null());
        dest = mark();
        LOG(debug) << "Found breakpoint break at " << dest;
        final_result = result;
        final_tuid = result.break_status.task ? result.break_status.task->tuid()
                                              : TaskUid();
        last_stop_is_watch_or_signal = false;
        at_breakpoint = true;
      } else {
        at_breakpoint = false;
      }
    }

    if (dest) {
      if (last_stop_is_watch_or_signal) {
        LOG(debug)
            << "Performing final reverse-singlestep to pass over watch/signal";
        reverse_singlestep(dest, final_tuid);
      } else {
        LOG(debug) << "Seeking to final destination " << dest;
        seek_to_mark(dest);
      }
      final_result.break_status.task = current->find_task(final_tuid);
      assert(final_result.break_status.reason != BREAK_NONE);
      return final_result;
    }

    // No breakpoint was hit. Retry from an earlier checkpoint.
    end = start;
  }
}

class AutoCheckpoint {
public:
  AutoCheckpoint(ReplayTimeline& timeline) : timeline(timeline) {
    m = timeline.add_explicit_checkpoint();
  }
  ~AutoCheckpoint() { timeline.remove_explicit_checkpoint(m); }
  const ReplayTimeline::Mark& mark() { return m; }

private:
  ReplayTimeline& timeline;
  ReplayTimeline::Mark m;
};

ReplayResult ReplayTimeline::reverse_singlestep(const Mark& origin,
                                                const TaskUid& tuid) {
  ReplayResult result;

  LOG(debug) << "ReplayTimeline::reverse_singlestep from " << origin;

  while (true) {
    Mark end = origin;
    do {
      MarkKey current_key = end.ptr->key;
      while (true) {
        if (end.ptr->key.trace_time != current_key.trace_time ||
            end.ptr->key.ticks != current_key.ticks) {
          break;
        }
        seek_to_before_key(current_key);
        if (current_mark_key() == current_key) {
          // Can't go further back. Treat this as an exit.
          LOG(debug) << "Couldn't seek to before " << end << ", returning exit";
          result.status = REPLAY_EXITED;
          result.break_status.reason = BREAK_NONE;
          return result;
        }
        LOG(debug) << "Seeked backward from " << current_key << " to "
                   << current_mark_key();
        current_key = current_mark_key();
      }

      Mark start = mark();
      LOG(debug) << "Running forward from " << start;
      // Now run forward until we're reasonably close to the correct tick value.
      do {
        unapply_breakpoints_and_watchpoints();
        Task* t = current->current_task();
        if (t->tuid() == tuid) {
          result =
              current->replay_step(RUN_CONTINUE, 0, origin.ptr->key.ticks - 1);
          if (result.break_status.reason == BREAK_TICKS_TARGET) {
            LOG(debug) << "   reached ticks target";
            break;
          }
        } else {
          current->replay_step(RUN_CONTINUE);
        }
      } while (current_mark() != end.ptr);
      end = start;
    } while (result.break_status.reason != BREAK_TICKS_TARGET);
    assert(current->current_task()->tuid() == tuid);

    Mark destination_candidate;
    // Take a checkpoint now, before we start stepping, so the
    // final seek_to_mark is fast
    AutoCheckpoint stepping_started(*this);
    Mark step_start = stepping_started.mark();
    ReplayResult destination_candidate_result;

    while (true) {
      Mark now;
      unapply_breakpoints_and_watchpoints();
      if (current->current_task()->tuid() == tuid) {
        result = current->replay_step(RUN_SINGLESTEP);
        now = mark();
        LOG(debug) << "Singlestepped towards target, now at " << now;
        if (result.break_status.reason == BREAK_SINGLESTEP ||
            result.break_status.reason == BREAK_SIGNAL ||
            result.break_status.reason == BREAK_WATCHPOINT) {
          if (now > origin) {
            // This last step is not usable.
            LOG(debug) << "   not usable, stopping now";
            break;
          }
          destination_candidate = step_start;
          LOG(debug) << "New destination candidate is "
                     << destination_candidate;
          destination_candidate_result = result;
          step_start = now;
        }
      } else {
        result = current->replay_step(RUN_CONTINUE);
        now = mark();
        LOG(debug) << "Wrong task, ran towards target, now at " << now;
      }
      if (now >= origin) {
        break;
      }
    }

    if (destination_candidate) {
      seek_to_mark(destination_candidate);
      LOG(debug) << "Seeked to destination " << destination_candidate;
      destination_candidate_result.break_status.task = current->find_task(tuid);
      assert(destination_candidate_result.break_status.task);
      assert(destination_candidate_result.break_status.reason != BREAK_NONE);
      return destination_candidate_result;
    }
  }
}

ReplayResult ReplayTimeline::replay_step(RunCommand command,
                                         RunDirection direction,
                                         TraceFrame::Time stop_at_time) {
  if (direction == RUN_FORWARD) {
    apply_breakpoints_and_watchpoints();
    current->set_visible_execution(true);
    auto result = current->replay_step(command, stop_at_time);
    current->set_visible_execution(false);
    return result;
  }

  assert(stop_at_time == 0 && "stop_at_time unsupported for reverse execution");

  switch (command) {
    case RUN_CONTINUE:
      return reverse_continue();
    case RUN_SINGLESTEP:
      return reverse_singlestep(mark(), current->current_task()->tuid());
    default:
      assert(0 && "Unknown RunCommand");
      return ReplayResult();
  }
}

ReplayTimeline::Progress ReplayTimeline::estimate_progress() {
  Session::Statistics stats = current->statistics();
  // The following parameters were estimated by running Firefox startup
  // and shutdown in an opt build on a Lenovo W530 laptop, replaying with
  // DUMP_STATS_PERIOD set to 100 (twice, and using only values from the
  // second run, to ensure caches are warm), and then minimizing least-squares
  // error.
  static const double microseconds_per_tick = 0.0020503143;
  static const double microseconds_per_syscall = 39.6793587609;
  static const double microseconds_per_byte_written = 0.001833611;
  static const double microseconds_constant = 997.8257239043;
  return Progress(microseconds_per_tick * stats.ticks_processed +
                  microseconds_per_syscall * stats.syscalls_performed +
                  microseconds_per_byte_written * stats.bytes_written +
                  microseconds_constant);
}
