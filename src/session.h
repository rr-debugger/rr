/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_SESSION_H_
#define RR_SESSION_H_

#include <cassert>
#include <map>
#include <memory>
#include <set>
#include <string>

#include "preload/syscall_buffer.h"

#include "trace.h"
#include "replayer.h"

class AddressSpace;
struct current_state_buffer;
class EmuFs;
class Task;
struct TaskGroup;
class TraceIfstream;
class TraceOfstream;
class RecordSession;
class ReplaySession;

/**
 * Sessions track the global state of a set of tracees corresponding
 * to an rr recorder or replayer.  During recording, the tracked
 * tracees will all write to the same TraceOfstream, and during
 * replay, the tracees that will be tracked will all be created based
 * on the same TraceIfstream.
 *
 * Sessions exist in order to allow multiple
 * TraceOfstream/TraceIfstreams to coexist in the same process.  This
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
  Task* clone(Task* p, int flags, void* stack, void* tls, void* cleartid_addr,
              pid_t new_tid, pid_t new_rec_tid = -1);

  /** Return a new task group consisting of |t|. */
  std::shared_ptr<TaskGroup> create_tg(Task* t);

  /** Call |Task::dump(out)| for all live tasks. */
  void dump_all_tasks(FILE* out = NULL);

  /**
   * Return the task created with |rec_tid|, or NULL if no such
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

/** Encapsulates additional session state related to recording. */
class RecordSession : public Session {
public:
  typedef std::shared_ptr<RecordSession> shr_ptr;

  /**
   * Fork and exec the initial tracee task to run |ae|.  Return
   * that Task.
   */
  Task* create_task(const struct args_env& ae, shr_ptr self);

  TraceOfstream& ofstream() { return *trace_ofstream; }

  /**
   * Create a recording session for the initial exe image
   * |exe_path|.  (That argument is used to name the trace
   * directory.)
   */
  static shr_ptr create(const std::string& exe_path);

  virtual RecordSession* as_record() { return this; }

private:
  std::shared_ptr<TraceOfstream> trace_ofstream;
};

/** Encapsulates additional session state related to replay. */
class ReplaySession : public Session {
public:
  typedef std::shared_ptr<ReplaySession> shr_ptr;

  ~ReplaySession();

  /**
   * Return a semantic copy of all the state managed by this,
   * that is the entire tracee tree and the state it depends on.
   * Any mutations of the returned Session can't affect the
   * state of this, and vice versa.
   *
   * This operation is also called "checkpointing" the replay
   * session.
   */
  shr_ptr clone();

  /**
   * Like |clone()|, but return a session in "diversion" mode,
   * which allows free execution.  The returned session has
   * exactly one ref().  See diversioner.h.
   */
  shr_ptr clone_diversion();

  /**
   * Fork and exec the initial tracee task to run |ae|, and read
   * recorded events from |trace|.  |rec_tid| is the recorded
   * tid of the initial tracee task.  Return that Task.
   */
  Task* create_task(const struct args_env& ae, shr_ptr self, pid_t rec_tid);

  EmuFs& emufs() { return *emu_fs; }

  /** Collect garbage files from this session's emufs. */
  void gc_emufs();

  TraceIfstream& ifstream() { return *trace_ifstream; }

  /**
   * True when this diversion is dying, as determined by
   * clients.
   */
  bool diversion_dying() const {
    assert(is_diversion);
    return 0 == diversion_refcount;
  }

  /**
   * True when this is an diversion session; see diversioner.h.
   */
  bool diversion() const { return is_diversion; }

  /**
   * The trace record that we are working on --- the next event
   * for replay to reach.
   */
  struct trace_frame& current_trace_frame() { return trace_frame; }
  /**
   * State of the replay as we advance towards the event given by
   * current_trace_frame().
   */
  struct rep_trace_step& current_replay_step() { return replay_step; }

  byte* syscallbuf_flush_buffer() { return syscallbuf_flush_buffer_array; }
  const struct syscallbuf_hdr* syscallbuf_flush_buffer_hdr() {
    return (const struct syscallbuf_hdr*)syscallbuf_flush_buffer_array;
  }

  bool& reached_trace_frame() { return trace_frame_reached; }

  /**
   * Set |tgid| as the one that's being debugged in this
   * session.
   *
   * Little hack: technically replayer doesn't know about the
   * fact that debugger_gdb hides all but one tgid from the gdb
   * client.  But to recognize the last_task below (another
   * little hack), we need to known when an exiting thread from
   * the target task group is the last.
   */
  void set_debugged_tgid(pid_t tgid) {
    assert(0 == tgid_debugged);
    tgid_debugged = tgid;
  }
  pid_t debugged_tgid() const { return tgid_debugged; }

  /**
   * Set |t| as the last (debugged) task in this session.
   *
   * When we notify the debugger of process exit, it wants to be
   * able to poke around at that last task.  So we store it here
   * to allow processing debugger requests for it later.
   */
  void set_last_task(Task* t) {
    assert(!last_debugged_task);
    last_debugged_task = t;
  }
  Task* last_task() { return last_debugged_task; }

  /**
   * Add another reference to this diversion, which specifically
   * means another call to |diversion_unref()| must be made
   * before this is considered to be dying.
   */
  void diversion_ref() {
    assert(is_diversion);
    assert(diversion_refcount >= 0);
    ++diversion_refcount;
  }

  /**
   * Remove a reference to this diversion created by
   * |diversion_ref()|.
   */
  void diversion_unref() {
    assert(is_diversion);
    assert(diversion_refcount > 0);
    --diversion_refcount;
  }

  /**
   * Create a replay session that will use the trace specified
   * by the commad-line args |argc|/|argv|.  Return it.
   */
  static shr_ptr create(int argc, char* argv[]);

  EnvironmentBugDetector& bug_detector() { return environment_bug_detector; }

  virtual ReplaySession* as_replay() { return this; }

private:
  ReplaySession()
      : diversion_refcount(0),
        is_diversion(false),
        last_debugged_task(nullptr),
        tgid_debugged(0),
        trace_frame(),
        replay_step(),
        trace_frame_reached(false) {}

  std::shared_ptr<EmuFs> emu_fs;
  // Number of client references to this, if it's a diversion
  // session.  When there are 0 refs this is considered to be
  // dying.
  int diversion_refcount;
  // True when this is an "diversion" session; see
  // diversioner.h.  In the future, this will be a separate
  // DiversionSession class.
  bool is_diversion;
  Task* last_debugged_task;
  pid_t tgid_debugged;
  std::shared_ptr<TraceIfstream> trace_ifstream;
  struct trace_frame trace_frame;
  struct rep_trace_step replay_step;
  EnvironmentBugDetector environment_bug_detector;
  /**
   * Buffer for recorded syscallbuf bytes.  By definition buffer flushes
   * must be replayed sequentially, so we can use one buffer for all
   * tracees.  At the start of the flush, the recorded bytes are read
   * back into this buffer.  Then they're copied back to the tracee
   * record-by-record, as the tracee exits those syscalls.
   * This needs to be word-aligned.
   */
  byte syscallbuf_flush_buffer_array[SYSCALLBUF_BUFFER_SIZE];
  /**
   * True when the session has reached the state in trace_frame.
   * False when the session is working towards the state in trace_frame.
   */
  bool trace_frame_reached;
};

#endif // RR_SESSION_H_
