/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

//#define DEBUGTAG "RecordSession"

#include "RecordSession.h"

#include "task.h"

using namespace rr;
using namespace std;

Task* RecordSession::create_task() {
  Task* t = Task::spawn(*this);
  track(t);
  return t;
}

/*static*/ RecordSession::shr_ptr RecordSession::create(
    const std::vector<std::string>& argv, const std::vector<std::string>& envp,
    const string& cwd, int bind_to_cpu) {
  shr_ptr session(new RecordSession(argv, envp, cwd, bind_to_cpu));
  return session;
}

RecordSession::RecordSession(const std::vector<std::string>& argv,
                             const std::vector<std::string>& envp,
                             const string& cwd, int bind_to_cpu)
    : trace_out(argv, envp, cwd, bind_to_cpu) {}

void RecordSession::update_task_priority(Task* t, int value) {
  if (t->priority == value) {
    return;
  }
  if (t->in_round_robin_queue) {
    t->priority = value;
    return;
  }
  task_priority_set.erase(make_pair(t->priority, t));
  t->priority = value;
  task_priority_set.insert(make_pair(t->priority, t));
}

void RecordSession::schedule_one_round_robin(Task* t) {
  if (!task_round_robin_queue.empty()) {
    return;
  }

  for (auto iter : task_priority_set) {
    if (iter.second != t) {
      task_round_robin_queue.push_back(iter.second);
      iter.second->in_round_robin_queue = true;
    }
  }
  task_round_robin_queue.push_back(t);
  t->in_round_robin_queue = true;
  task_priority_set.clear();
}

Task* RecordSession::get_next_round_robin_task() {
  if (task_round_robin_queue.empty()) {
    return nullptr;
  }

  return task_round_robin_queue.front();
}

void RecordSession::remove_round_robin_task() {
  assert(!task_round_robin_queue.empty());

  Task* t = task_round_robin_queue.front();
  task_round_robin_queue.pop_front();
  if (t) {
    t->in_round_robin_queue = false;
    task_priority_set.insert(make_pair(t->priority, t));
  }
}
