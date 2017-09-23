/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "ThreadGroup.h"

#include "Session.h"
#include "Task.h"
#include "ThreadDb.h"
#include "log.h"

namespace rr {

ThreadGroup::ThreadGroup(Session* session, ThreadGroup* parent, pid_t tgid,
                         pid_t real_tgid, uint32_t serial)
    : tgid(tgid),
      real_tgid(real_tgid),
      dumpable(true),
      execed(false),
      received_sigframe_SIGSEGV(false),
      session_(session),
      parent_(parent),
      serial(serial) {
  LOG(debug) << "creating new task group " << tgid
             << " (real tgid:" << real_tgid << ")";
  if (parent) {
    parent->children_.insert(this);
  }
  session->on_create(this);
}

ThreadGroup::~ThreadGroup() {
  if (session_) {
    session_->on_destroy(this);
  }
  for (ThreadGroup* tg : children()) {
    tg->parent_ = nullptr;
  }
  if (parent_) {
    parent_->children_.erase(this);
  }
}

void ThreadGroup::destabilize() {
  LOG(debug) << "destabilizing task group " << tgid;
  for (auto it = task_set().begin(); it != task_set().end(); ++it) {
    Task* t = *it;
    t->unstable = true;
    LOG(debug) << "  destabilized task " << t->tid;
  }
}

ThreadDb* ThreadGroup::thread_db() {
  if (!thread_db_) {
    thread_db_ = std::unique_ptr<ThreadDb>(new ThreadDb(this));
  }
  return thread_db_.get();
}

} // namespace rr
