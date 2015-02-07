/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

//#define DEBUGTAG "ReplayTimeline"
#include "ReplayTimeline.h"

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
    : session_flags(session_flags), current(std::move(session)) {
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
  } else {
    // Now the hard part: figuring out where to put it in the list of existing
    // marks.
    // XXX if we hit this path at all often, an easy optimization would be
    // to track whether 'current' is known to be after all marks on the list.
    // Run forward from the current point in a temporary session and see
    // which Marks (if any) we hit.
    ReplaySession::shr_ptr tmp_session = current->clone();
    size_t mark_index = run_to_mark_or_tick(*tmp_session, mark_vector);
    // mark_index is the current index of the next mark after 'current'. So
    // insert our new mark at mark_index.
    mark_vector.insert(mark_vector.begin() + mark_index, m);
  }
  swap(m, result.ptr);
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
    auto result = session.replay_step(Session::RUN_SINGLESTEP);
    if (session_mark_key(session) != key) {
      return marks.size();
    }

    switch (result.status) {
      case ReplaySession::REPLAY_CONTINUE: {
        Task* t = session.current_task();
        for (size_t i = 0; i < marks.size(); ++i) {
          shared_ptr<InternalMark> m(marks[i]);
          if (!t || m->regs.matches(t->regs())) {
            return i;
          }
        }
        break;
      }
      case ReplaySession::REPLAY_EXITED:
        // We didn't hit any marks...
        return marks.size();
    }
  }

  return marks.size();
}

ReplayTimeline::Mark ReplayTimeline::add_explicit_checkpoint() {
  assert_no_breakpoints_set();
  Mark m = mark();
  if (!m.ptr->checkpoint) {
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
    }
  }
}

void ReplayTimeline::assert_no_breakpoints_set() {
  for (auto& vm : current->vms()) {
    assert(!vm->has_breakpoints());
    assert(!vm->has_watchpoints());
  }
}

void ReplayTimeline::seek_up_to_mark(const Mark& mark) {
  assert_no_breakpoints_set();
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
        return;
      }
      if (m == mark.ptr) {
        break;
      }
    }
  }

  return seek_to_before_key(mark.ptr->key);
}

void ReplayTimeline::seek_to_mark(const Mark& mark) {
  assert_no_breakpoints_set();
  seek_up_to_mark(mark);
  while (current_mark() != mark.ptr) {
    if (current->trace_reader().time() < mark.ptr->key.trace_time) {
      current->replay_step(Session::RUN_CONTINUE, mark.ptr->key.trace_time);
    } else {
      Task* t = current->current_task();
      assert(t && "Multiple marks for state with no task?");
      if (t->regs().ip() == mark.ptr->regs.ip()) {
        // At required IP, but not in the correct state. Singlestep over
        // this IP.
        current->replay_step(Session::RUN_SINGLESTEP);
      } else {
        t->vm()->add_breakpoint(mark.ptr->regs.ip(), TRAP_BKPT_USER);
        current->replay_step(Session::RUN_CONTINUE);
        t->vm()->remove_breakpoint(mark.ptr->regs.ip(), TRAP_BKPT_USER);
      }
    }
  }
}
