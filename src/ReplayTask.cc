/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "ReplayTask.h"

#include "log.h"
#include "ReplaySession.h"

using namespace rr;
using namespace std;

ReplayTask::ReplayTask(ReplaySession& session, pid_t _tid, pid_t _rec_tid,
                       uint32_t serial, SupportedArch a)
    : Task(session, _tid, _rec_tid, serial, a) {}

ReplaySession& ReplayTask::session() const {
  return *Task::session().as_replay();
}
