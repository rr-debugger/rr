/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

//#define DEBUGTAG "ReplayTimeline"

#include "ReplayTimeline.h"

#include <math.h>

#include "fast_forward.h"
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

ostream& operator<<(ostream& s, const ReplayTimeline::ProtoMark& o) {
  return s << "{" << o.key << ",regs_ip:" << HEX(o.regs.ip().as_int()) << "}";
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

ReplayTimeline::ProtoMark ReplayTimeline::proto_mark() const {
  return ProtoMark(current_mark_key(), current->current_task()->regs());
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
    // simplest thing and just single-step until we find where to put the new
    // mark(s).
    vector<shared_ptr<InternalMark> > new_marks;
    new_marks.push_back(m);

    LOG(debug) << "mark() replaying to find mark location";

    // Allow coalescing of multiple repetitions of a single x86 string
    // instruction (as long as we don't reach one of our mark_vector states).
    ReplaySession::StepConstraints constraints(RUN_SINGLESTEP_FAST_FORWARD);
    for (auto& mv : mark_vector) {
      constraints.stop_before_states.push_back(&mv->regs);
    }

    while (true) {
      auto result = tmp_session->replay_step(constraints);
      if (session_mark_key(*tmp_session) != key ||
          result.status != REPLAY_CONTINUE) {
        break;
      }
      if (!result.break_status.singlestep_complete) {
        continue;
      }

      Task* t = tmp_session->current_task();
      for (auto it = mark_vector.begin(); it != mark_vector.end(); ++it) {
        shared_ptr<InternalMark>& existing_mark = *it;
        if (equal_regs(existing_mark->regs, t->regs())) {
          if (!result.did_fast_forward && !result.break_status.signal) {
            new_marks.back()->singlestep_to_next_mark_no_signal = true;
          }
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
      if (!result.did_fast_forward && !result.break_status.signal) {
        new_marks.back()->singlestep_to_next_mark_no_signal = true;
      }
      new_marks.push_back(make_shared<InternalMark>(this, t, key));
    }

    LOG(debug) << "Mark location found";

    // mark_index is the current index of the next mark after 'current'. So
    // insert our new marks at mark_index.
    mark_vector.insert(mark_index, new_marks.begin(), new_marks.end());
  }
  swap(m, result.ptr);
  current_at_or_after_mark = result.ptr;
  return result;
}

void ReplayTimeline::mark_after_singlestep(const Mark& from,
                                           const ReplayResult& result) {
  Mark m = mark();
  if (!result.did_fast_forward && m.ptr->key == from.ptr->key &&
      !result.break_status.signal) {
    auto& mark_vector = marks[m.ptr->key];
    for (size_t i = 0; i < mark_vector.size(); ++i) {
      if (mark_vector[i] == from.ptr) {
        assert(i + 1 < mark_vector.size() && mark_vector[i + 1] == m.ptr);
        break;
      }
    }
    from.ptr->singlestep_to_next_mark_no_signal = true;
  }
}

ReplayTimeline::Mark ReplayTimeline::find_singlestep_before(const Mark& mark) {
  auto& mark_vector = marks[mark.ptr->key];
  ssize_t i;
  for (i = mark_vector.size() - 1; i >= 0; --i) {
    if (mark_vector[i] == mark.ptr) {
      break;
    }
  }
  assert(i >= 0 && "Mark not in vector???");

  Mark m;
  if (i == 0) {
    return m;
  }
  if (!mark_vector[i - 1]->singlestep_to_next_mark_no_signal) {
    return m;
  }
  m.ptr = mark_vector[i - 1];
  return m;
}

ReplayTimeline::Mark ReplayTimeline::lazy_reverse_singlestep(const Mark& from,
                                                             Task* t) {
  if (!no_watchpoints_hit_interval_start || !no_watchpoints_hit_interval_end) {
    return Mark();
  }
  Mark m = find_singlestep_before(from);
  if (m && m >= no_watchpoints_hit_interval_start &&
      m < no_watchpoints_hit_interval_end &&
      !has_breakpoint_at_address(t, from.ptr->regs.ip())) {
    return m;
  }
  return Mark();
}

ReplayTimeline::Mark ReplayTimeline::add_explicit_checkpoint() {
  assert(current->can_clone());

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
          // At this point, m->checkpoint is fully initialized but current
          // is not. Swap them so that m->checkpoint is not fully
          // initialized, to reduce resource usage.
          swap(current, m->checkpoint);
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
  }

  // Check if any of the marks with the same key as 'mark', but not after
  // 'mark', are usable.
  auto& mark_vector = marks[mark.ptr->key];
  bool at_or_before_mark = false;
  for (ssize_t i = mark_vector.size() - 1; i >= 0; --i) {
    auto& m = mark_vector[i];
    if (m == mark.ptr) {
      at_or_before_mark = true;
    }
    if (at_or_before_mark && m->checkpoint) {
      current = m->checkpoint->clone();
      // At this point, m->checkpoint is fully initialized but current
      // is not. Swap them so that m->checkpoint is not fully
      // initialized, to reduce resource usage.
      swap(current, m->checkpoint);
      breakpoints_applied = false;
      current_at_or_after_mark = m;
      return;
    }
  }

  return seek_to_before_key(mark.ptr->key);
}

ReplayResult ReplayTimeline::replay_step_to_mark(const Mark& mark) {
  ReplayResult result;
  if (current->trace_reader().time() < mark.ptr->key.trace_time) {
    ReplaySession::StepConstraints constraints(RUN_CONTINUE);
    constraints.stop_at_time = mark.ptr->key.trace_time;
    result = current->replay_step(constraints);
  } else {
    Task* t = current->current_task();
    remote_ptr<uint8_t> mark_addr = mark.ptr->regs.ip();
    if (t->regs().ip() == mark_addr &&
        current->current_step_key().in_execution()) {
      // At required IP, but not in the correct state. Singlestep over
      // this IP.
      ReplaySession::StepConstraints constraints(RUN_SINGLESTEP_FAST_FORWARD);
      constraints.stop_before_states.push_back(&mark.ptr->regs);
      result = current->replay_step(constraints);
      // Hide internal singlestep but preserve other break statuses
      result.break_status.singlestep_complete = false;
    } else {
      ProtoMark before = proto_mark();
      {
        // Get a shared reference to t->vm() in case t dies during replay_step
        shared_ptr<AddressSpace> vm = t->vm();
        vm->add_breakpoint(mark_addr, TRAP_BKPT_USER);
        result = current->replay_step(RUN_CONTINUE);
        vm->remove_breakpoint(mark_addr, TRAP_BKPT_USER);
      }
      // If we hit our breakpoint and there is no client breakpoint there,
      // pretend we didn't hit it.
      if (result.break_status.breakpoint_hit &&
          breakpoints.count(make_pair(result.break_status.task->vm()->uid(),
                                      result.break_status.task->ip())) == 0) {
        result.break_status.breakpoint_hit = false;
      }
      fix_watchpoint_coalescing_quirk(result, before);
    }
  }
  return result;
}

void ReplayTimeline::seek_to_proto_mark(const ProtoMark& pmark) {
  seek_to_before_key(pmark.key);
  unapply_breakpoints_and_watchpoints();
  while (current_mark_key() != pmark.key ||
         !equal_regs(current->current_task()->regs(), pmark.regs)) {
    if (current->trace_reader().time() < pmark.key.trace_time) {
      ReplaySession::StepConstraints constraints(RUN_CONTINUE);
      constraints.stop_at_time = pmark.key.trace_time;
      current->replay_step(constraints);
    } else {
      Task* t = current->current_task();
      remote_ptr<uint8_t> mark_addr = pmark.regs.ip();
      if (t->regs().ip() == mark_addr &&
          current->current_step_key().in_execution()) {
        // At required IP, but not in the correct state. Singlestep over
        // this IP.
        ReplaySession::StepConstraints constraints(RUN_SINGLESTEP_FAST_FORWARD);
        constraints.stop_before_states.push_back(&pmark.regs);
        current->replay_step(constraints);
      } else {
        // Get a shared reference to t->vm() in case t dies during replay_step
        shared_ptr<AddressSpace> vm = t->vm();
        vm->add_breakpoint(mark_addr, TRAP_BKPT_USER);
        current->replay_step(RUN_CONTINUE);
        vm->remove_breakpoint(mark_addr, TRAP_BKPT_USER);
      }
    }
  }
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

/**
 * Intel CPUs (and maybe others) coalesce iterations of REP-prefixed string
 * instructions so that a watchpoint on a byte at location L can fire after
 * the iteration that writes byte L+63 (or possibly more?).
 * This causes problems for rr since this coalescing doesn't happen when we
 * single-step.
 * This function is called after doing a ReplaySession::replay_step with
 * command == RUN_CONTINUE. RUN_SINGLESTEP and RUN_SINGLESTEP_FAST_FORWARD
 * disable this coalescing (the latter, because it's aware of watchpoings
 * and single-steps when it gets too close to them).
 * |before| is the state before we did the replay_step.
 * If a watchpoint fired, and it looks like it could have fired during a
 * string instruction, we'll backup to |before| and replay forward, stopping
 * before the breakpoint could fire and single-stepping to make sure the
 * coalescing quirk doesn't happen.
 */
void ReplayTimeline::fix_watchpoint_coalescing_quirk(ReplayResult& result,
                                                     const ProtoMark& before) {
  if (result.status == REPLAY_EXITED ||
      result.break_status.watchpoints_hit.empty()) {
    // no watchpoint hit. Nothing to fix.
    return;
  }
  if (!maybe_at_or_after_x86_string_instruction(result.break_status.task)) {
    return;
  }

  TaskUid after_tuid = result.break_status.task->tuid();
  Ticks after_ticks = result.break_status.task->tick_count();
  LOG(debug) << "Fixing x86-string coalescing quirk from " << before << " to "
             << proto_mark() << " (final cx "
             << result.break_status.task->regs().cx() << ")";

  seek_to_proto_mark(before);

  // Keep going until the watchpoint fires. It will either fire early, or at
  // the same time as some other break.
  apply_breakpoints_and_watchpoints();
  bool approaching_ticks_target = false;
  while (true) {
    Task* t = current->current_task();
    if (t->tuid() == after_tuid) {
      if (approaching_ticks_target) {
        // We don't need to set any stop_before_states here.
        // RUN_SINGLESTEP_FAST_FORWARD always avoids the coalescing quirk, so
        // if a watchpoint is triggered by the string instruction at
        // string_instruction_ip, it will have the correct timing.
        result = current->replay_step(RUN_SINGLESTEP_FAST_FORWARD);
        if (!result.break_status.watchpoints_hit.empty()) {
          LOG(debug) << "Fixed x86-string coalescing quirk; now at "
                     << current_mark_key() << " (new cx "
                     << result.break_status.task->regs().cx() << ")";
          break;
        }
      } else {
        ReplaySession::StepConstraints constraints(RUN_CONTINUE);
        constraints.ticks_target = after_ticks - 1;
        result = current->replay_step(constraints);
        approaching_ticks_target = result.break_status.approaching_ticks_target;
      }
      ASSERT(t, t->tick_count() <= after_ticks) << "We went too far!";
    } else {
      current->replay_step(RUN_CONTINUE);
    }
  }
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
  no_watchpoints_hit_interval_start = no_watchpoints_hit_interval_start =
      Mark();
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
      result.break_status = BreakStatus();
      return result;
    }
    maybe_add_reverse_exec_checkpoint(EXPECT_SHORT_REVERSE_EXECUTION);

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
        // This will remove all reverse-exec checkpoints ahead of the
        // current time, and add new ones if necessary. This should be
        // helpful if we have to reverse-continue far back in time, where
        // the interval between 'start' and 'end' could be lengthy; we'll
        // populate the interval with new checkpoints, speeding up
        // the following seek and possibly future operations.
      }
      maybe_add_reverse_exec_checkpoint(EXPECT_SHORT_REVERSE_EXECUTION);
      if (!result.break_status.watchpoints_hit.empty() ||
          result.break_status.signal) {
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
      if (result.break_status.breakpoint_hit) {
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
      // fix break_status.task since the actual Task* may have changed
      // since we saved final_result
      final_result.break_status.task = current->find_task(final_tuid);
      // Hide any singlestepping we did, since a continue operation should
      // never return a singlestep status
      final_result.break_status.singlestep_complete = false;
      return final_result;
    }

    // No breakpoint was hit. Retry from an earlier checkpoint.
    end = start;
  }
}

ReplayResult ReplayTimeline::reverse_singlestep(const Mark& origin,
                                                const TaskUid& tuid) {
  ReplayResult result;

  LOG(debug) << "ReplayTimeline::reverse_singlestep from " << origin;

  while (true) {
    Mark end = origin;
    while (true) {
      MarkKey current_key = end.ptr->key;
      while (true) {
        if (end.ptr->key.trace_time != current_key.trace_time ||
            end.ptr->key.ticks != current_key.ticks) {
          break;
        }
        seek_to_before_key(current_key);
        maybe_add_reverse_exec_checkpoint(EXPECT_SHORT_REVERSE_EXECUTION);
        if (current_mark_key() == current_key) {
          // Can't go further back. Treat this as an exit.
          LOG(debug) << "Couldn't seek to before " << end << ", returning exit";
          result.status = REPLAY_EXITED;
          result.break_status = BreakStatus();
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
          ReplaySession::StepConstraints constraints(RUN_CONTINUE);
          constraints.ticks_target = end.ptr->key.ticks - 1;
          result = current->replay_step(constraints);
          if (result.break_status.approaching_ticks_target) {
            LOG(debug) << "   approached ticks target at "
                       << current_mark_key();
            break;
          }
        } else {
          current->replay_step(RUN_CONTINUE);
        }
        maybe_add_reverse_exec_checkpoint(EXPECT_SHORT_REVERSE_EXECUTION);
      } while (current_mark() != end.ptr);
      if (result.break_status.approaching_ticks_target) {
        break;
      }
      end = start;
    }
    assert(current->current_task()->tuid() == tuid);

    Mark destination_candidate;
    Mark step_start = mark();
    ReplayResult destination_candidate_result;

    no_watchpoints_hit_interval_start = Mark();
    while (true) {
      Mark now;
      if (current->current_task()->tuid() == tuid) {
        apply_breakpoints_and_watchpoints();
        Mark before_step = mark();
        ReplaySession::StepConstraints constraints(RUN_SINGLESTEP_FAST_FORWARD);
        constraints.stop_before_states.push_back(&end.ptr->regs);
        result = current->replay_step(constraints);
        if (result.break_status.breakpoint_hit) {
          unapply_breakpoints_and_watchpoints();
          result = current->replay_step(constraints);
        }
        now = mark();
        if (result.break_status.singlestep_complete) {
          mark_after_singlestep(before_step, result);
          if (now > end) {
            // This last step is not usable.
            LOG(debug) << "   not usable, stopping now";
            break;
          }
          destination_candidate = step_start;
          destination_candidate_result = result;
          step_start = now;
          if (!no_watchpoints_hit_interval_start ||
              !result.break_status.watchpoints_hit.empty()) {
            no_watchpoints_hit_interval_start = now;
          }
        }
      } else {
        unapply_breakpoints_and_watchpoints();
        result = current->replay_step(RUN_CONTINUE);
        no_watchpoints_hit_interval_start = Mark();
        now = mark();
      }
      if (now >= end) {
        break;
      }
      maybe_add_reverse_exec_checkpoint(EXPECT_SHORT_REVERSE_EXECUTION);
    }
    no_watchpoints_hit_interval_end =
        no_watchpoints_hit_interval_start ? end : Mark();

    if (destination_candidate) {
      LOG(debug) << "Found destination " << destination_candidate;
      seek_to_mark(destination_candidate);
      destination_candidate_result.break_status.task = current->find_task(tuid);
      assert(destination_candidate_result.break_status.task);
      return destination_candidate_result;
    }
  }
}

ReplayResult ReplayTimeline::replay_step(RunCommand command,
                                         RunDirection direction,
                                         TraceFrame::Time stop_at_time) {
  assert(command != RUN_SINGLESTEP_FAST_FORWARD);

  ReplayResult result;
  if (direction == RUN_FORWARD) {
    apply_breakpoints_and_watchpoints();
    ProtoMark before = proto_mark();
    current->set_visible_execution(true);
    ReplaySession::StepConstraints constraints(command);
    constraints.stop_at_time = stop_at_time;
    result = current->replay_step(constraints);
    current->set_visible_execution(false);
    if (command == RUN_CONTINUE) {
      // Since it's easy for us to fix the coalescing quirk for forward
      // execution, we may as well do so. It's nice to have forward execution
      // behave consistently with reverse execution.
      fix_watchpoint_coalescing_quirk(result, before);
      // Hide any singlestepping we did
      result.break_status.singlestep_complete = false;
    }
    maybe_add_reverse_exec_checkpoint(LOW_OVERHEAD);
  } else {
    assert(stop_at_time == 0 &&
           "stop_at_time unsupported for reverse execution");

    switch (command) {
      case RUN_CONTINUE:
        result = reverse_continue();
        break;
      case RUN_SINGLESTEP:
        result = reverse_singlestep(mark(), current->current_task()->tuid());
        break;
      default:
        assert(0 && "Unknown RunCommand");
        return ReplayResult();
    }
  }
  return result;
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

/*
 * Checkpointing strategy:
 *
 * We define a series of intervals of increasing length, each one ending at
 * the current replay position. In each interval N, we allow at most N
 * checkpoints. We ensure that interval lengths grow exponentially (in the
 * limit), so the maximum number of checkpoints for a given execution length
 * L is O(log L).
 *
 * Interval N has length inter_checkpoint_interval to the
 * power of checkpoint_interval_exponent.
 * We allow at most N checkpoints in interval N.
 * To discard excess checkpoints, first pick the smallest interval N with
 * too many checkpoints, and discard the latest checkpoint in interval N
 * that is not in interval N-1. Repeat until there are no excess checkpoints.
 * All checkpoints after the current replay point are always discarded.
 * The script checkpoint-visualizer.html simulates this algorithm and
 * visualizes its results.
 * The implementation here is quite naive, but that's OK because we will
 * never have a large number of checkpoints.
 */

/**
 * Try to space out our checkpoints by a minimum of this much in LOW_OVERHEAD
 * mode.
 * This is currently aiming for about 0.5s of replay time, so a reverse step or
 * continue whose destination is within 0.5 should take at most a second.
 * Also, based on a guesstimate that taking checkpoints of Firefox requires
 * about 50ms, this would make checkpointing overhead about 10% of replay time,
 * which sounds reasonable.
 */
static ReplayTimeline::Progress low_overhead_inter_checkpoint_interval = 500000;

/**
 * Space out checkpoints linearly by this much in
 * EXPECT_SHORT_REVERSE_EXECUTION mode, until we reach
 * low_overhead_inter_checkpoint_interval.
 */
static ReplayTimeline::Progress
expecting_reverse_exec_inter_checkpoint_interval = 100000;

/**
 * Make each interval this much bigger than the previous.
 */
static float checkpoint_interval_exponent = 2;

static ReplayTimeline::Progress inter_checkpoint_interval(
    ReplayTimeline::CheckpointStrategy strategy) {
  return strategy == ReplayTimeline::LOW_OVERHEAD
             ? low_overhead_inter_checkpoint_interval
             : expecting_reverse_exec_inter_checkpoint_interval;
}

static ReplayTimeline::Progress next_interval_length(
    ReplayTimeline::Progress len) {
  if (len >= low_overhead_inter_checkpoint_interval) {
    return (ReplayTimeline::Progress)ceil(checkpoint_interval_exponent * len);
  }
  return len + expecting_reverse_exec_inter_checkpoint_interval;
}

void ReplayTimeline::maybe_add_reverse_exec_checkpoint(
    CheckpointStrategy strategy) {
  discard_future_reverse_exec_checkpoints();

  Progress now = estimate_progress();
  auto it = reverse_exec_checkpoints.rbegin();
  if (it != reverse_exec_checkpoints.rend() &&
      it->second >= now - inter_checkpoint_interval(strategy)) {
    // Latest checkpoint is close enough; we don't need to do anything.
    return;
  }

  if (!current->can_clone()) {
    // We can't create a checkpoint right now.
    return;
  }

  // We always discard checkpoints before adding the new one to reduce the
  // maximum checkpoint count by one.
  discard_past_reverse_exec_checkpoints(strategy);

  reverse_exec_checkpoints[add_explicit_checkpoint()] = now;
}

void ReplayTimeline::discard_future_reverse_exec_checkpoints() {
  Progress now = estimate_progress();
  while (true) {
    auto it = reverse_exec_checkpoints.rbegin();
    if (it == reverse_exec_checkpoints.rend() || it->second < now) {
      break;
    }
    remove_explicit_checkpoint(it->first);
    reverse_exec_checkpoints.erase(it->first);
  }
}

void ReplayTimeline::discard_past_reverse_exec_checkpoints(
    CheckpointStrategy strategy) {
  Progress now = estimate_progress();
  // No checkpoints are allowed in the first interval, since we're about to
  // add one there.
  int checkpoints_allowed = 0;
  int checkpoints_in_range = 0;
  auto it = reverse_exec_checkpoints.rbegin();
  vector<Mark> checkpoints_to_delete;
  for (Progress len = inter_checkpoint_interval(strategy);;
       len = next_interval_length(len)) {
    Progress start = now - len;
    // Count checkpoints >= start, starting at 'it', and leave the first
    // checkpoint entry < start in 'tmp_it'.
    auto tmp_it = it;
    while (tmp_it != reverse_exec_checkpoints.rend() &&
           tmp_it->second >= start) {
      ++checkpoints_in_range;
      ++tmp_it;
    }
    // Delete excess checkpoints starting with 'it'.
    while (checkpoints_in_range > checkpoints_allowed) {
      checkpoints_to_delete.push_back(it->first);
      --checkpoints_in_range;
      ++it;
    }
    ++checkpoints_allowed;
    it = tmp_it;
    if (it == reverse_exec_checkpoints.rend()) {
      break;
    }
  }

  for (auto& m : checkpoints_to_delete) {
    remove_explicit_checkpoint(m);
    reverse_exec_checkpoints.erase(m);
  }
}
