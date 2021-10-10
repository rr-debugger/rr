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
    if (!t->already_exited() && !t->is_dying()) {
      return t;
    }
  }
  return nullptr;
}

} // namespace rr
