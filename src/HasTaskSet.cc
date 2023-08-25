/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "HasTaskSet.h"

#include "Task.h"
#include "log.h"

namespace rr {

void HasTaskSet::insert_task(Task* t) {
  LOG(debug) << "adding " << t->tid << " to task set " << this;
  tasks.insert(t);
}

void HasTaskSet::erase_task(Task* t) {
  LOG(debug) << "removing " << t->tid << " from task set " << this;
  tasks.erase(t);
}

Task* HasTaskSet::first_running_task() const {
  for (auto t : task_set()) {
    if (!t->already_exited() && !t->seen_ptrace_exit_event()) {
      return t;
    }
  }
  return nullptr;
}

Task* HasTaskSet::find_other_thread_group(Task* t) const {
  for (Task* tt : task_set()) {
    if (tt->thread_group() != t->thread_group()) {
      return tt;
    }
  }
  return nullptr;
}

} // namespace rr
