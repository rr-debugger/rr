/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "HasTaskSet.h"

#include "log.h"
#include "Task.h"

void HasTaskSet::insert_task(Task* t) {
  LOG(debug) << "adding " << t->tid << " to task set " << this;
  tasks.insert(t);
}

void HasTaskSet::erase_task(Task* t) {
  LOG(debug) << "removing " << t->tid << " from task group " << this;
  tasks.erase(t);
}
