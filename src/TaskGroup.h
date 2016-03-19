/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_TASKGROUP_H_
#define RR_TASKGROUP_H_

#include <sched.h>
#include <stdint.h>

#include <memory>
#include <set>

#include "HasTaskSet.h"
#include "TaskishUid.h"

class Session;

/**
 * Tracks a group of tasks with an associated ID, set from the
 * original "thread group leader", the child of |fork()| which became
 * the ancestor of all other threads in the group.  Each constituent
 * task must own a reference to this.
 */
class TaskGroup : public HasTaskSet {
public:
  TaskGroup(Session* session, TaskGroup* parent, pid_t tgid, pid_t real_tgid,
            uint32_t serial);
  ~TaskGroup();

  typedef std::shared_ptr<TaskGroup> shr_ptr;

  /** See |Task::destabilize_task_group()|. */
  void destabilize();

  const pid_t tgid;
  const pid_t real_tgid;

  int exit_code;

  Session* session() const { return session_; }
  void forget_session() { session_ = nullptr; }

  TaskGroup* parent() { return parent_; }

  TaskGroupUid tguid() const { return TaskGroupUid(tgid, serial); }

  // We don't allow tasks to make themselves undumpable. If they try,
  // record that here and lie about it if necessary.
  bool dumpable;

private:
  TaskGroup(const TaskGroup&) = delete;
  TaskGroup operator=(const TaskGroup&) = delete;

  Session* session_;
  /** Parent TaskGroup, or nullptr if it's not a tracee (rr or init). */
  TaskGroup* parent_;

  std::set<TaskGroup*> children;

  uint32_t serial;
};

#endif /* RR_TASKGROUP_H_ */
