/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_SESSION_H_
#define RR_SESSION_H_

#include <cassert>
#include <map>
#include <memory>
#include <set>
#include <string>

#include "TraceStream.h"

class AddressSpace;
class Task;
struct TaskGroup;
class RecordSession;
class ReplaySession;

/**
 * Sessions track the global state of a set of tracees corresponding
 * to an rr recorder or replayer.  During recording, the tracked
 * tracees will all write to the same TraceWriter, and during
 * replay, the tracees that will be tracked will all be created based
 * on the same TraceReader.
 *
 * Multiple sessions can coexist in the same process.  This
 * is required when using replay checkpoints, for example.
 */
class Session {
  friend class ReplaySession;

public:
  typedef std::set<AddressSpace*> AddressSpaceSet;
  typedef std::map<pid_t, Task*> TaskMap;
  // Tasks sorted by priority.
  typedef std::set<std::pair<int, Task*> > TaskPrioritySet;
  typedef std::deque<Task*> TaskQueue;

  /**
   * Call |after_exec()| after a tracee has successfully
   * |execve()|'d.  After that, |can_validate()| return true.
   *
   * Tracee state can't be validated before the first exec,
   * because the address space inside the rr process for |rr
   * replay| will be different than it was for |rr record|.
   * After the first exec, we're running tracee code, and
   * everything must be the same.
   */
  void after_exec();
  bool can_validate() const { return tracees_consistent; }

  /**
   * Create and return a new address space that's constructed
   * from |t|'s actual OS address space.
   */
  std::shared_ptr<AddressSpace> create_vm(Task* t, const std::string& exe);
  /**
   * Return a copy of |vm| with the same mappings.  If any
   * mapping is changed, only the |clone()|d copy is updated,
   * not its origin (i.e. copy-on-write semantics).
   */
  std::shared_ptr<AddressSpace> clone(std::shared_ptr<AddressSpace> vm);

  /** See Task::clone(). */
  Task* clone(Task* p, int flags, remote_ptr<void> stack,
              remote_ptr<void> tls, remote_ptr<int> cleartid_addr,
              pid_t new_tid, pid_t new_rec_tid = -1);

  /** Return a new task group consisting of |t|. */
  std::shared_ptr<TaskGroup> create_tg(Task* t);

  /** Call |Task::dump(out)| for all live tasks. */
  void dump_all_tasks(FILE* out = nullptr);

  /**
   * Return the task created with |rec_tid|, or nullptr if no such
   * task exists.
   */
  Task* find_task(pid_t rec_tid);

  /**
   * |tasks().size()| will be zero and all the OS tasks will be
   * gone when this returns, or this won't return.
   */
  void kill_all_tasks();

  /**
   * Call these functions from the objects' destructors in order
   * to notify this session that the objects are dying.
   */
  void on_destroy(AddressSpace* vm);
  void on_destroy(Task* t);

  /** Return the set of Tasks being tracekd in this session. */
  const TaskMap& tasks() const { return task_map; }

  /** Get tasks organized by priority. */
  const TaskPrioritySet& tasks_by_priority() { return task_priority_set; }

  /**
   * Set the priority of |t| to |value| and update related
   * state.
   */
  void update_task_priority(Task* t, int value);

  /**
   * Do one round of round-robin scheduling if we're not already doing one.
   * If we start round-robin scheduling now, make last_task the last
   * task to be scheduled.
   * If the task_round_robin_queue is empty this moves all tasks into it,
   * putting last_task last.
   */
  void schedule_one_round_robin(Task* last_task);

  /**
   * Returns the first task in the round-robin queue or null if it's empty.
   */
  Task* get_next_round_robin_task();
  /**
   * Removes a task from the front of the round-robin queue.
   */
  void remove_round_robin_task();

  /**
   * Return the set of AddressSpaces being tracked in this session.
   */
  const AddressSpaceSet& vms() const { return sas; }

  virtual RecordSession* as_record() { return nullptr; }
  virtual ReplaySession* as_replay() { return nullptr; }

  bool is_recording() { return as_record() != nullptr; }

  virtual TraceStream& trace() = 0;

protected:
  Session();
  ~Session();

  void track(Task* t);

  AddressSpaceSet sas;
  TaskMap task_map;
  /**
   * Every task of this session is either in task_priority_set
   * (when in_round_robin_queue is false), or in task_round_robin_queue
   * (when in_round_robin_queue is true).
   *
   * task_priority_set is a set of pairs of (task->priority, task). This
   * lets us efficiently iterate over the tasks with a given priority, or
   * all tasks in priority order.
   */
  TaskPrioritySet task_priority_set;
  TaskQueue task_round_robin_queue;

  bool tracees_consistent;

  Session(const Session&) = delete;
  Session& operator=(const Session&) = delete;
};

#endif // RR_SESSION_H_
