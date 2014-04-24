/* -*- Mode: C++; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#ifndef RR_SESSION_H_
#define RR_SESSION_H_

#include <map>
#include <memory>
#include <set>

class AddressSpace;
class Task;
struct TaskGroup;
class TraceIfstream;
class TraceOfstream;

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
public:
	typedef std::shared_ptr<Session> shr_ptr;
	typedef std::set<AddressSpace*> AddressSpaceSet;
	typedef std::map<pid_t, Task*> TaskMap;
	// Tasks sorted by priority.
	typedef std::set<std::pair<int, Task*> > TaskPrioritySet;

	/**
	 * Create and return a new address space that's constructed
	 * from |t|'s actual OS address space.
	 */
	std::shared_ptr<AddressSpace> create_vm(Task* t);
	/**
	 * Return a copy of |vm| with the same mappings.  If any
	 * mapping is changed, only the |clone()|d copy is updated,
	 * not its origin (i.e. copy-on-write semantics).
	 */
	std::shared_ptr<AddressSpace> clone(std::shared_ptr<AddressSpace> vm);

	/**
	 * Fork and exec the initial tracee task to run |ae|, and
	 * record events into |trace|.  Return that Task.
	 */
	Task* create_task(const struct args_env& ae,
			  std::shared_ptr<TraceOfstream> trace);
	/**
	 * Fork and exec the initial tracee task to run |ae|, and read
	 * recorded events from |trace|.  |rec_tid| is the recorded
	 * tid of the initial tracee task.  Return that Task.
	 */
	Task* create_task(const struct args_env& ae,
			  std::shared_ptr<TraceIfstream> trace, pid_t rec_tid);
	/** See Task::clone(). */
	Task* clone(Task* p, int flags, void* stack, void* cleartid_addr,
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
	const TaskPrioritySet& tasks_by_priority() { return task_priority_set;}

	/**
	 * Set the priority of |t| to |value| and update related
	 * state.
	 */
	void update_task_priority(Task* t, int value);

	/**
	 * Return the set of AddressSpaces being tracked in this session.
	 */
	const AddressSpaceSet& vms() const { return sas; }

	/** Return the session that's currently being used. */
	static shr_ptr current();

private:
	Session() {}

	void track(Task* t);

	AddressSpaceSet sas;
	TaskMap task_map;
	TaskPrioritySet task_priority_set;

	// XXX for now, there's only one session.  That will change in
	// the future.
	static shr_ptr session;

	Session(const Session&) = delete;
	Session& operator=(const Session&) = delete;
};

#endif // RR_SESSION_H_
