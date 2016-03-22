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
  typedef std::set<Task*> TaskSet;

  const TaskSet& task_set() const { return tasks; }

  void insert_task(Task* t);
  void erase_task(Task* t);
  bool has_task(Task* t) const { return tasks.find(t) != tasks.end(); }

protected:
  TaskSet tasks;
};

} // namespace rr

#endif /* RR_HASTASKSET_H_ */
