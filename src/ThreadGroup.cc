/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "ThreadGroup.h"

#include "RecordTask.h"
#include "Session.h"
#include "Task.h"
#include "ThreadDb.h"
#include "log.h"

namespace rr {

ThreadGroup::ThreadGroup(Session* session, ThreadGroup* parent,
                         pid_t tgid, pid_t tgid_own_namespace,
                         uint32_t serial)
    : tgid(tgid),
      tgid_own_namespace(tgid_own_namespace),
      dumpable(true),
      execed(false),
      received_sigframe_SIGSEGV(false),
      session_(session),
      parent_(parent),
      first_run_event_(0),
      serial(serial) {
  LOG(debug) << "creating new thread group " << tgid;
  if (parent) {
    parent->children_.insert(this);
  }
  session->on_create(this);
}

ThreadGroup::shr_ptr ThreadGroup::shared_from_this() {
  return (*tasks.begin())->thread_group();
}

ThreadGroup::~ThreadGroup() {
  if (session_) {
    session_->on_destroy(this);
  }
  if (parent_) {
    parent_->children_.erase(this);
  }
  for (ThreadGroup* tg : children()) {
    tg->parent_ = nullptr;
    // We don't fix the parenting during replay. Currently
    // nothing depends on parenting during replay.
    if (session_ && session_->is_recording()) {
      auto it = tg->task_set().begin();
      if (it != tg->task_set().end()) {
        const RecordTask* rt = static_cast<const RecordTask*>(*it);
        pid_t ppid = rt->get_parent_pid();
        tg->parent_ = session_->find_thread_group(ppid);
        if (tg->parent_) {
          tg->parent_->children_.insert(tg);
        }
      }
    }
  }
}

} // namespace rr
