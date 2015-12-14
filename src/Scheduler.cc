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

using namespace rr;
using namespace std;

Task* Scheduler::get_next_task_with_same_priority(Task* t) {
  if (!t || t->in_round_robin_queue) {
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

int Scheduler::choose_random_priority() { return random() % priority_levels; }

/**
 * Returns true if we should return t as the runnable task. Otherwise we
 * should check the next task.
 */
static bool is_task_runnable(Task* t, bool* by_waitpid) {
  if (t->unstable) {
    LOG(debug) << "  " << t->tid << " is unstable";
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

  if (EV_SYSCALL == t->ev().type() &&
      PROCESSING_SYSCALL == t->ev().Syscall().state &&
      is_sched_yield_syscall(t->ev().Syscall().number, t->arch())) {
    // sched_yield syscalls never really blocks but the kernel may report that
    // the task is not stopped yet if we pass WNOHANG. To make sched_yield
    // behave predictably, do a blocking wait.
    t->wait();
    LOG(debug) << "  sched_yield ready with status " << HEX(t->status());
    *by_waitpid = true;
    return true;
  }

  LOG(debug) << "  " << t->tid << " is blocked on " << t->ev()
             << "; checking status ...";
  bool did_wait_for_t;
  did_wait_for_t = t->try_wait();
  if (did_wait_for_t) {
    *by_waitpid = true;
    LOG(debug) << "  ready with status " << HEX(t->status());
    return true;
  }
  LOG(debug) << "  still blocked";
  // Try next task
  return false;
}

Task* Scheduler::find_next_runnable_task(Task* t, bool* by_waitpid) {
  *by_waitpid = false;

  while (true) {
    Task* next = take_next_round_robin_task();
    if (!next) {
      break;
    }
    LOG(debug) << "Trying task " << next->tid << " from yield queue";
    if (is_task_runnable(next, by_waitpid)) {
      return next;
    }
    maybe_pop_round_robin_task(next);
  }

  // The outer loop has one iteration per unique priority value.
  // The inner loop iterates over all tasks with that priority.
  for (auto same_priority_start = task_priority_set.begin();
       same_priority_start != task_priority_set.end();) {
    int priority = same_priority_start->first;
    auto same_priority_end = task_priority_set.lower_bound(
        make_pair(same_priority_start->first + 1, nullptr));

    if (enable_chaos) {
      vector<Task*> tasks;
      for (auto it = same_priority_start; it != same_priority_end; ++it) {
        tasks.push_back(it->second);
      }
      random_shuffle(tasks.begin(), tasks.end());
      for (Task* next : tasks) {
        if (is_task_runnable(next, by_waitpid)) {
          return next;
        }
      }
    } else {
      auto begin_at = same_priority_start;
      if (t && priority == t->priority) {
        begin_at = task_priority_set.find(make_pair(priority, t));
        ++begin_at;
        if (begin_at == same_priority_end) {
          begin_at = same_priority_start;
        }
      }

      auto task_iterator = begin_at;
      do {
        Task* next = task_iterator->second;

        if (is_task_runnable(next, by_waitpid)) {
          return next;
        }

        ++task_iterator;
        if (task_iterator == same_priority_end) {
          task_iterator = same_priority_start;
        }
      } while (task_iterator != begin_at);
    }

    same_priority_start = same_priority_end;
  }

  return nullptr;
}

void Scheduler::setup_new_timeslice(Task* t) {
  Ticks timeslice_duration = max_ticks_;
  if (enable_chaos) {
    // Hypothesis: some bugs require short timeslices to expose. But we don't
    // want the average timeslice to be too small. So make 10% of timeslices
    // very short, 10% short-ish, and the rest uniformly distributed between 0
    // and |max_size|.
    switch (random() % 10) {
      case 0:
        timeslice_duration = random() % min<Ticks>(max_ticks_, 100);
        break;
      case 1:
        timeslice_duration = random() % min<Ticks>(max_ticks_, 10000);
        break;
      default:
        timeslice_duration = random() % max_ticks_;
    }
  }
  t->timeslice_end = t->tick_count() + timeslice_duration;
}

void Scheduler::maybe_reset_priorities() {
  if (!enable_chaos) {
    return;
  }
  if (events_until_reset_priorities > 0) {
    --events_until_reset_priorities;
    return;
  }
  // Reset task priorities again at some point in the future.
  events_until_reset_priorities = random() % 10000;
  vector<Task*> tasks;
  for (auto p : task_priority_set) {
    tasks.push_back(p.second);
  }
  for (Task* t : task_round_robin_queue) {
    tasks.push_back(t);
  }
  for (Task* t : tasks) {
    update_task_priority_internal(t, choose_random_priority());
  }
}

Task* Scheduler::get_next_thread(Task* t, Switchable switchable,
                                 bool* by_waitpid) {
  LOG(debug) << "Scheduling next task";

  *by_waitpid = false;

  if (!current) {
    current = t;
  }
  assert(!t || t == current);

  maybe_reset_priorities();

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

  if (current && !current->unstable && !always_switch &&
      current->tick_count() < current->timeslice_end &&
      is_task_runnable(current, by_waitpid)) {
    return current;
  }

  LOG(debug) << "  need to reschedule";

  Task* next = find_next_runnable_task(current, by_waitpid);
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

  setup_new_timeslice(next);
  current = next;
  return current;
}

void Scheduler::on_create(Task* t) {
  assert(!t->in_round_robin_queue);
  if (enable_chaos) {
    // new tasks get a random priority
    t->priority = choose_random_priority();
  }
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
  if (!enable_chaos) {
    update_task_priority_internal(t, value);
  }
}

void Scheduler::update_task_priority_internal(Task* t, int value) {
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
  ASSERT(t, !t->in_round_robin_queue);

  for (auto iter : task_priority_set) {
    if (iter.second != t && !iter.second->in_round_robin_queue) {
      task_round_robin_queue.push_back(iter.second);
      iter.second->in_round_robin_queue = true;
    }
  }
  task_priority_set.clear();
  task_round_robin_queue.push_back(t);
  t->in_round_robin_queue = true;
  t->expire_timeslice();
}

Task* Scheduler::take_next_round_robin_task() {
  if (task_round_robin_queue.empty()) {
    return nullptr;
  }

  Task* t = task_round_robin_queue.front();
  task_round_robin_queue.pop_front();
  t->in_round_robin_queue = false;
  task_priority_set.insert(make_pair(t->priority, t));
  return t;
}
