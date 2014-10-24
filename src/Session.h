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

  /**
   * Call |after_exec()| after a tracee has successfully
   * |execve()|'d.  After that, |can_validate()| returns true.
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
  Task* clone(Task* p, int flags, remote_ptr<void> stack, remote_ptr<void> tls,
              remote_ptr<int> cleartid_addr, pid_t new_tid,
              pid_t new_rec_tid = -1);

  /**
   * Return the task created with |rec_tid|, or nullptr if no such
   * task exists.
   */
  Task* find_task(pid_t rec_tid) const;

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
  virtual void on_destroy(Task* t);

  /** Return the set of Tasks being tracekd in this session. */
  const TaskMap& tasks() const { return task_map; }

  /**
   * Return the set of AddressSpaces being tracked in this session.
   */
  const AddressSpaceSet& vms() const { return sas; }

  virtual RecordSession* as_record() { return nullptr; }
  virtual ReplaySession* as_replay() { return nullptr; }

  bool is_recording() { return as_record() != nullptr; }

  // The following types are used by step() APIs in Session subclasses.

  enum BreakReason {
    BREAK_NONE,
    // A requested RUN_SINGLESTEP completed.
    BREAK_SINGLESTEP,
    // We hit a breakpoint.
    BREAK_BREAKPOINT,
    // We hit a watchpoint.
    BREAK_WATCHPOINT,
    // We hit a signal.
    BREAK_SIGNAL
  };
  struct BreakStatus {
    BreakReason reason;
    // When break_reason is not BREAK_NONE, the triggering Task.
    Task* task;
    // When break_reason is BREAK_SIGNAL, the signal.
    int signal;
    // When break_reason is BREAK_WATCHPOINT, the triggering watch address.
    remote_ptr<void> watch_address;
  };
  enum RunCommand {
    RUN_CONTINUE,
    RUN_SINGLESTEP
  };

protected:
  Session();
  ~Session();

  virtual void on_create(Task* t);

  AddressSpaceSet sas;
  TaskMap task_map;

  /**
   * True if we've done an exec so tracees are now in a state that will be
   * consistent across record and replay.
   */
  bool tracees_consistent;

  Session(const Session&) = delete;
  Session& operator=(const Session&) = delete;
};

#endif // RR_SESSION_H_
