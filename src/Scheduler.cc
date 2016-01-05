/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

//#define DEBUGTAG "Scheduler"
//#define MONITOR_UNSWITCHABLE_WAITS

#include "Scheduler.h"

#include <assert.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <algorithm>

#include "Flags.h"
#include "log.h"
#include "RecordSession.h"
#include "task.h"

using namespace std;

static void note_switch(Task* prev_t, Task* t) {
  if (prev_t == t) {
    t->succ_event_counter++;
  } else {
    t->succ_event_counter = 0;
  }
}

Task* Scheduler::get_next_task_with_same_priority(Task* t) {
  if (t->in_round_robin_queue) {
    return nullptr;
  }

  auto it = task_priority_set.find(make_pair(t->priority, t));
  assert(it != task_priority_set.end());
  ++it;
  if (it == task_priority_set.end() || it->first != t->priority) {
    it = task_priority_set.lower_bound(make_pair(t->priority, nullptr));
  }
  return it->second;
}

/**
 * Returns true if we should return t as the runnable task. Otherwise we
 * should check the next task.
 */
static bool is_task_runnable(Task* t, bool* by_waitpid) {
  if (t->unstable) {
    LOG(debug) << "  " << t->tid << " is unstable, doing waitpid(-1)";
    return true;
  }

  if (!t->may_be_blocked()) {
    LOG(debug) << "  " << t->tid << " isn't blocked";
    return true;
  }

  if (t->emulated_stop_type != NOT_STOPPED) {
    LOG(debug) << "  " << t->tid << " is stopped by ptrace or signal";
    return false;
  }

  LOG(debug) << "  " << t->tid << " is blocked on " << t->ev()
             << "; checking status ...";
  bool did_wait_for_t;
  if (t->pseudo_blocked) {
    t->wait();
    did_wait_for_t = true;
  } else {
    did_wait_for_t = t->try_wait();
  }
  if (did_wait_for_t) {
    t->pseudo_blocked = false;
    *by_waitpid = true;
    LOG(debug) << "  ready with status " << HEX(t->status());
    return true;
  }
  LOG(debug) << "  still blocked";
  // Try next task
  return false;
}

Task* Scheduler::find_next_runnable_task(bool* by_waitpid) {
  *by_waitpid = false;

  while (true) {
    Task* t = get_next_round_robin_task();
    if (!t) {
      break;
    }
    LOG(debug) << "Choosing task " << t->tid << " from yield queue";
    if (is_task_runnable(t, by_waitpid)) {
      return t;
    }
    // This task had its chance to run but couldn't. Move to the
    // next task in the queue.
    remove_round_robin_task();
  }

  // The outer loop has one iteration per unique priority value.
  // The inner loop iterates over all tasks with that priority.
  for (auto same_priority_start = task_priority_set.begin();
       same_priority_start != task_priority_set.end();) {
    int priority = same_priority_start->first;
    auto same_priority_end = task_priority_set.lower_bound(
        make_pair(same_priority_start->first + 1, nullptr));

    auto begin_at = same_priority_start;
    if (current && priority == current->priority) {
      begin_at = task_priority_set.find(make_pair(priority, current));
    }

    auto task_iterator = begin_at;
    do {
      Task* t = task_iterator->second;

      if (is_task_runnable(t, by_waitpid)) {
        return t;
      }

      ++task_iterator;
      if (task_iterator == same_priority_end) {
        task_iterator = same_priority_start;
      }
    } while (task_iterator != begin_at);

    same_priority_start = same_priority_end;
  }

  return nullptr;
}

Task* Scheduler::get_next_thread(Task* t, Switchable switchable,
                                 bool* by_waitpid) {
  LOG(debug) << "Scheduling next task";

  *by_waitpid = false;

  if (!current) {
    current = t;
  }
  assert(!t || t == current);

  if (t && switchable == PREVENT_SWITCH) {
    LOG(debug) << "  (" << current->tid << " is un-switchable at "
               << current->ev() << ")";
    if (current->is_running()) {
      LOG(debug) << "  and running; waiting for state change";
/* |current| is un-switchable, but already running. Wait for it to change state
 * before "scheduling it", so avoid busy-waiting with our client. */
#ifdef MONITOR_UNSWITCHABLE_WAITS
      double start = monotonic_now_sec(), wait_duration;
#endif
      current->wait();
#ifdef MONITOR_UNSWITCHABLE_WAITS
      wait_duration = monotonic_now_sec() - start;
      if (wait_duration >= 0.010) {
        log_warn("Waiting for unswitchable %s took %g ms",
                 strevent(current->event), 1000.0 * wait_duration);
      }
#endif
      *by_waitpid = true;
      LOG(debug) << "  new status is " << HEX(current->status());
    }
    return current;
  }

  /* Prefer switching to the next task if the current one
   * exceeded its event limit. */
  if (current && current->succ_event_counter > max_events) {
    LOG(debug) << "  previous task exceeded event limit, preferring next";
    current->succ_event_counter = 0;
    if (current == get_next_round_robin_task()) {
      remove_round_robin_task();
    }
    current = get_next_task_with_same_priority(current);
  }

  Task* next = find_next_runnable_task(by_waitpid);

  if (next && !next->unstable) {
    LOG(debug) << "  selecting task " << next->tid;
  } else {
    // All the tasks are blocked (or we found an unstable-exit task).
    // Wait for the next one to change state.
    int status;
    pid_t tid;

    LOG(debug) << "  all tasks blocked or some unstable, waiting for runnable ("
               << task_priority_set.size() << " total)";
    do {
      tid = waitpid(-1, &status, __WALL | WSTOPPED | WUNTRACED);
      if (-1 == tid) {
        if (EINTR == errno) {
          LOG(debug) << "  waitpid(-1) interrupted";
          return nullptr;
        }
        FATAL() << "Failed to waitpid()";
      }
      LOG(debug) << "  " << tid << " changed status to " << HEX(status);

      next = session.find_task(tid);
      if (!next) {
        LOG(debug) << "    ... but it's dead";
      }
    } while (!next);
    ASSERT(next,
           next->unstable || next->may_be_blocked() ||
               Task::ptrace_event_from_status(status) == PTRACE_EVENT_EXIT)
        << "Scheduled task should have been blocked or unstable";
    next->did_waitpid(status);
    *by_waitpid = true;
  }

  note_switch(current, next);
  current = next;
  return current;
}

void Scheduler::on_create(Task* t) {
  assert(!t->in_round_robin_queue);
  task_priority_set.insert(make_pair(t->priority, t));
}

void Scheduler::on_destroy(Task* t) {
  if (t == current) {
    current = get_next_task_with_same_priority(t);
    if (t == current) {
      current = nullptr;
    }
  }

  if (t->in_round_robin_queue) {
    auto iter =
        find(task_round_robin_queue.begin(), task_round_robin_queue.end(), t);
    task_round_robin_queue.erase(iter);
  } else {
    task_priority_set.erase(make_pair(t->priority, t));
  }
}

void Scheduler::update_task_priority(Task* t, int value) {
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

void Scheduler::schedule_one_round_robin(Task* t) {
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

Task* Scheduler::get_next_round_robin_task() {
  if (task_round_robin_queue.empty()) {
    return nullptr;
  }

  return task_round_robin_queue.front();
}

void Scheduler::remove_round_robin_task() {
  assert(!task_round_robin_queue.empty());

  Task* t = task_round_robin_queue.front();
  task_round_robin_queue.pop_front();
  if (t) {
    t->in_round_robin_queue = false;
    task_priority_set.insert(make_pair(t->priority, t));
  }
}
