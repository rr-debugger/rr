/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

//#define DEBUGTAG "ReplayTimeline"
#include "ReplayTimeline.h"

#include "log.h"

using namespace rr;
using namespace std;

ReplayTimeline::InternalMark::~InternalMark() {
  if (owner) {
    auto& mark_vector = owner->marks[key];
    for (auto it = mark_vector.begin(); it != mark_vector.end(); ++it) {
      if (it->expired()) {
        mark_vector.erase(it);
        break;
      }
    }
    if (mark_vector.empty()) {
      owner->marks.erase(key);
    }
    if (checkpoint) {
      owner->remove_mark_with_checkpoint(key);
    }
  }
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
  for (weak_ptr<InternalMark>& m_weak : m1.ptr->owner->marks[m1.ptr->key]) {
    shared_ptr<InternalMark> m(m_weak);
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
    for (weak_ptr<InternalMark>& itv : it.second) {
      itv.lock().get()->owner = nullptr;
    }
  }
}

shared_ptr<ReplayTimeline::InternalMark> ReplayTimeline::current_mark() {
  Task* t = current->current_task();
  for (weak_ptr<InternalMark>& m_weak : marks[current_mark_key()]) {
    shared_ptr<InternalMark> m(m_weak);
    if (!t || m->regs.matches(t->regs())) {
      return m;
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
  } else if (mark_vector[mark_vector.size() - 1].lock() ==
             current_at_or_after_mark.ptr) {
    mark_vector.push_back(m);
  } else {
    // Now the hard part: figuring out where to put it in the list of existing
    // marks.
    // XXX if we hit this path at all often, an easy optimization would be
    // to track whether 'current' is known to be after all marks on the list.
    // Run forward from the current point in a temporary session and see
    // which Marks (if any) we hit.
    unapply_breakpoints_and_watchpoints();
    ReplaySession::shr_ptr tmp_session = current->clone();
    size_t mark_index = run_to_mark_or_tick(*tmp_session, mark_vector);
    // mark_index is the current index of the next mark after 'current'. So
    // insert our new mark at mark_index.
    mark_vector.insert(mark_vector.begin() + mark_index, m);
  }
  swap(m, result.ptr);
  current_at_or_after_mark = result;
  return result;
}

size_t ReplayTimeline::run_to_mark_or_tick(
    ReplaySession& session, const vector<weak_ptr<InternalMark> >& marks) {
  // We could set breakpoints at the marks and then continue with an
  // interrupt set to fire when our tick-count increases. But that requires
  // new replay functionality (probably a new RunCommand), so for now, do the
  // simplest thing and just single-step until the MarkKey has increased.
  MarkKey key = session_mark_key(session);
  while (true) {
    auto result = session.replay_step(RUN_SINGLESTEP);
    if (session_mark_key(session) != key) {
      return marks.size();
    }

    switch (result.status) {
      case REPLAY_CONTINUE: {
        Task* t = session.current_task();
        for (size_t i = 0; i < marks.size(); ++i) {
          shared_ptr<InternalMark> m(marks[i]);
          if (!t || m->regs.matches(t->regs())) {
            return i;
          }
        }
        break;
      }
      case REPLAY_EXITED:
        // We didn't hit any marks...
        return marks.size();
    }
  }

  return marks.size();
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
      current_at_or_after_mark = Mark();
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
      current_at_or_after_mark = Mark();
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
    for (weak_ptr<InternalMark>& m_weak : marks[mark.ptr->key]) {
      shared_ptr<InternalMark> m(m_weak);
      if (m->checkpoint) {
        current = m->checkpoint->clone();
        breakpoints_applied = false;
        current_at_or_after_mark = Mark();
        return;
      }
      if (m == mark.ptr) {
        break;
      }
    }
  }

  return seek_to_before_key(mark.ptr->key);
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
      if (result.break_status.reason == BREAK_SINGLESTEP) {
        result.break_status.reason = BREAK_NONE;
      }
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
      if (result.break_status.reason == BREAK_BREAKPOINT &&
          t->regs().ip() == mark_addr && breakpoints.count(p) == 0) {
        result.break_status.reason = BREAK_NONE;
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
  current_at_or_after_mark = mark;
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
  while (true) {
    seek_to_before_key(end.ptr->key);
    if (current_mark_key() == end.ptr->key) {
      // Can't go backwards. Call this an exit.
      result.status = REPLAY_EXITED;
      result.break_status.reason = BREAK_NONE;
      return result;
    }
    Mark start = mark();
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
        dest = mark();
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
      seek_to_mark(dest);
      if (last_stop_is_watch_or_signal) {
        reverse_singlestep(false);
      }
      final_result.break_status.task = current->find_task(final_tuid);
      return final_result;
    }

    // No breakpoint was hit. Retry from an earlier checkpoint.
    end = start;
  }
}

ReplayResult ReplayTimeline::reverse_singlestep(bool enable_breakpoints) {
  ReplayResult result;

  // If there's a breakpoint at the current location, singlestepping
  // backwards should just break without moving anywhere (just as if we
  // tried to singlestep forwards).
  if (enable_breakpoints &&
      has_breakpoint_at_address(current->current_task(),
                                current->current_task()->ip())) {
    result.status = REPLAY_CONTINUE;
    result.break_status.reason = BREAK_BREAKPOINT;
    result.break_status.task = current->current_task();
    result.break_status.watch_address = nullptr;
    return result;
  }

  Mark origin = mark();
  TaskUid tuid = current->current_task()->tuid();
  Ticks current_count = current->current_task()->tick_count();

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
          result.status = REPLAY_EXITED;
          result.break_status.reason = BREAK_NONE;
          return result;
        }
        current_key = current_mark_key();
      }

      Mark start = mark();
      // Now run forward until we're reasonably close to the correct tick value.
      do {
        unapply_breakpoints_and_watchpoints();
        Task* t = current->current_task();
        if (t->tuid() == tuid) {
          result = current->replay_step(RUN_CONTINUE, 0, current_count - 1);
          if (result.break_status.reason == BREAK_TICKS_TARGET) {
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
    Mark step_start = mark();
    assert(destination_candidate != origin);
    ReplayResult destination_candidate_result;

    while (true) {
      Mark now;
      unapply_breakpoints_and_watchpoints();
      if (current->current_task()->tuid() == tuid) {
        result = current->replay_step(RUN_SINGLESTEP);
        now = mark();
        if (result.break_status.reason == BREAK_SINGLESTEP ||
            result.break_status.reason == BREAK_SIGNAL ||
            result.break_status.reason == BREAK_WATCHPOINT) {
          if (now > origin) {
            // This last step is not usable.
            break;
          }
          destination_candidate = step_start;
          destination_candidate_result = result;
          step_start = now;
        }
      } else {
        result = current->replay_step(RUN_CONTINUE);
        now = mark();
      }
      if (now >= origin) {
        break;
      }
    }

    if (destination_candidate) {
      seek_to_mark(destination_candidate);
      destination_candidate_result.break_status.task =
          current->find_task(tuid.tid());
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
      break;
    case RUN_SINGLESTEP:
      return reverse_singlestep();
      break;
    default:
      assert(0 && "Unknown RunCommand");
      return ReplayResult();
  }
}
