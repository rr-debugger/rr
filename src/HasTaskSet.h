/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_HASTASKSET_H_
#define RR_HASTASKSET_H_

#include <set>

namespace rr {

class Task;

/**
 * Base class for classes that manage a set of Tasks.
 */
class HasTaskSet {
public:
  // Has virtual methods, therefore must have virtual destructor
  virtual ~HasTaskSet() {}

  typedef std::set<Task*> TaskSet;

  const TaskSet& task_set() const { return tasks; }

  virtual void insert_task(Task* t);
  virtual void erase_task(Task* t);
  bool has_task(Task* t) const { return tasks.find(t) != tasks.end(); }
  Task* find_other_thread_group(Task* t) const;
  Task* first_running_task() const;

protected:
  TaskSet tasks;
};

} // namespace rr

#endif /* RR_HASTASKSET_H_ */
