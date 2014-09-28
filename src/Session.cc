/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

//#define DEBUGTAG "Session"

#include "Session.h"

#include <syscall.h>
#include <sys/prctl.h>

#include <algorithm>

#include "log.h"
#include "task.h"
#include "util.h"

using namespace rr;
using namespace std;

Session::Session() : tracees_consistent(false) {
  LOG(debug) << "Session " << this << " created";
}

Session::~Session() {
  kill_all_tasks();
  LOG(debug) << "Session " << this << " destroyed";
}

void Session::after_exec() {
  if (tracees_consistent) {
    return;
  }
  tracees_consistent = true;
  // Reset ticks for all Tasks (there should only be one).
  for (auto task = tasks().begin(); task != tasks().end(); ++task) {
    task->second->flush_inconsistent_state();
  }
}

AddressSpace::shr_ptr Session::create_vm(Task* t, const std::string& exe) {
  AddressSpace::shr_ptr as(new AddressSpace(t, exe, *this));
  as->insert_task(t);
  sas.insert(as.get());
  return as;
}

AddressSpace::shr_ptr Session::clone(AddressSpace::shr_ptr vm) {
  AddressSpace::shr_ptr as(new AddressSpace(*vm));
  as->session = this;
  sas.insert(as.get());
  return as;
}

Task* Session::clone(Task* p, int flags, remote_ptr<void> stack,
                     remote_ptr<struct user_desc> tls,
                     remote_ptr<int> cleartid_addr, pid_t new_tid,
                     pid_t new_rec_tid) {
  Task* c = p->clone(flags, stack, tls, cleartid_addr, new_tid, new_rec_tid);
  track(c);
  return c;
}

TaskGroup::shr_ptr Session::create_tg(Task* t) {
  TaskGroup::shr_ptr tg(new TaskGroup(t->rec_tid, t->tid));
  tg->insert_task(t);
  return tg;
}

void Session::dump_all_tasks(FILE* out) {
  out = out ? out : stderr;

  for (auto as : sas) {
    auto ts = as->task_set();
    Task* t = *ts.begin();
    // XXX assuming that address space == task group,
    // which is almost certainly what the kernel enforces
    // too.
    fprintf(out, "\nTask group %d, image '%s':\n", t->tgid(),
            as->exe_image().c_str());
    for (auto tsit = ts.begin(); tsit != ts.end(); ++tsit) {
      (*tsit)->dump(out);
    }
  }
}

Task* Session::find_task(pid_t rec_tid) {
  auto it = tasks().find(rec_tid);
  return tasks().end() != it ? it->second : nullptr;
}

void Session::kill_all_tasks() {
  while (!task_map.empty()) {
    Task* t = task_map.rbegin()->second;
    LOG(debug) << "Killing " << t->tid << "(" << t << ")";
    t->kill();
    delete t;
  }
}

void Session::on_destroy(AddressSpace* vm) {
  assert(vm->task_set().size() == 0);
  assert(sas.end() != sas.find(vm));
  sas.erase(vm);
}

void Session::on_destroy(Task* t) {
  task_map.erase(t->rec_tid);
  if (t->in_round_robin_queue) {
    auto iter =
        find(task_round_robin_queue.begin(), task_round_robin_queue.end(), t);
    task_round_robin_queue.erase(iter);
  } else {
    task_priority_set.erase(make_pair(t->priority, t));
  }
}

void Session::track(Task* t) {
  task_map[t->rec_tid] = t;
  assert(!t->in_round_robin_queue);
  task_priority_set.insert(make_pair(t->priority, t));
}

void Session::update_task_priority(Task* t, int value) {
  if (t->in_round_robin_queue) {
    t->priority = value;
    return;
  }
  task_priority_set.erase(make_pair(t->priority, t));
  t->priority = value;
  task_priority_set.insert(make_pair(t->priority, t));
}

void Session::schedule_one_round_robin(Task* t) {
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

Task* Session::get_next_round_robin_task() {
  if (task_round_robin_queue.empty()) {
    return nullptr;
  }

  return task_round_robin_queue.front();
}

void Session::remove_round_robin_task() {
  assert(!task_round_robin_queue.empty());

  Task* t = task_round_robin_queue.front();
  task_round_robin_queue.pop_front();
  if (t) {
    t->in_round_robin_queue = false;
    task_priority_set.insert(make_pair(t->priority, t));
  }
}
