/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_TASKGROUP_H_
#define RR_TASKGROUP_H_

#include <sched.h>
#include <stdint.h>

#include <memory>
#include <set>

#include "HasTaskSet.h"
#include "TaskishUid.h"
#include "WaitStatus.h"
#include "TraceFrame.h"

namespace rr {

class Session;
class ThreadDb;

/**
 * Tracks a group of tasks with an associated ID, set from the
 * original "thread group leader", the child of |fork()| which became
 * the ancestor of all other threads in the group.  Each constituent
 * task must own a reference to this.
 */
class ThreadGroup : public HasTaskSet {
public:
  ThreadGroup(Session* session, ThreadGroup* parent, pid_t tgid,
              pid_t real_tgid, pid_t real_tgid_own_namespace,
              uint32_t serial);
  ~ThreadGroup();

  typedef std::shared_ptr<ThreadGroup> shr_ptr;

  const pid_t tgid;
  const pid_t real_tgid;
  const pid_t real_tgid_own_namespace;

  WaitStatus exit_status;

  Session* session() const { return session_; }
  void forget_session() { session_ = nullptr; }

  ThreadGroup* parent() { return parent_; }
  const std::set<ThreadGroup*>& children() { return children_; }

  ThreadGroupUid tguid() const { return ThreadGroupUid(tgid, serial); }

  FrameTime first_run_event() { return first_run_event_; }
  void set_first_run_event(FrameTime time) { first_run_event_ = time; }

  // We don't allow tasks to make themselves undumpable. If they try,
  // record that here and lie about it if necessary.
  bool dumpable;

  // Whether this thread group has execed
  bool execed;

  // True when a task in the task-group received a SIGSEGV because we
  // couldn't push a signal handler frame. Only used during recording.
  bool received_sigframe_SIGSEGV;

private:
  ThreadGroup(const ThreadGroup&) = delete;
  ThreadGroup operator=(const ThreadGroup&) = delete;

  Session* session_;
  /** Parent ThreadGroup, or nullptr if it's not a tracee (rr or init). */
  ThreadGroup* parent_;

  std::set<ThreadGroup*> children_;

  FrameTime first_run_event_;

  uint32_t serial;
};

} // namespace rr

#endif /* RR_TASKGROUP_H_ */
