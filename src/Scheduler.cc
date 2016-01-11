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

int Scheduler::choose_random_priority() {
  // Make a thread low-priority with probability 0.1
  return (random() % 10) ? 0 : 1;
}

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

Task* Scheduler::find_next_runnable_task(Task* t, bool* by_waitpid,
                                         int priority_threshold) {
  *by_waitpid = false;

  // The outer loop has one iteration per unique priority value.
  // The inner loop iterates over all tasks with that priority.
  for (auto same_priority_start = task_priority_set.begin();
       same_priority_start != task_priority_set.end();) {
    int priority = same_priority_start->first;
    if (priority > priority_threshold) {
      return nullptr;
    }
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

static void sleep_time(double t) {
  struct timespec ts;
  ts.tv_sec = (time_t)floor(t);
  ts.tv_nsec = (long)((t - ts.tv_sec) * 1e9);
  nanosleep(&ts, NULL);
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

static double random_frac() { return double(random() % INT32_MAX) / INT32_MAX; }

void Scheduler::maybe_reset_high_priority_only_intervals() {
  if (enable_chaos && high_priority_only_intervals_refresh_time == 0) {
    double now = monotonic_now_sec();
    // Stop scheduling low-priority threads for 0-2 seconds
    double duration = random_frac() * 2;
    // Make the schedule-stop 20% of the total run time
    double interval_length = duration * 5;
    double start = now + random_frac() * duration * 4;
    high_priority_only_intervals.push_back({ start, start + duration });
    high_priority_only_intervals_refresh_time = now + interval_length;
  }
}

bool Scheduler::in_high_priority_only_interval() {
  double now = monotonic_now_sec();
  for (auto& i : high_priority_only_intervals) {
    if (now >= i.start && now < i.end) {
      return true;
    }
  }
  return false;
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

  Task* next;
  while (true) {
    if (current) {
      next = get_round_robin_task()
                 ? nullptr
                 : find_next_runnable_task(current, by_waitpid,
                                           current->priority - 1);
      if (next) {
        break;
      }
      if (!next && !current->unstable && !always_switch &&
          current->tick_count() < current->timeslice_end &&
          is_task_runnable(current, by_waitpid)) {
        LOG(debug) << "  Carrying on with task " << current->tid;
        return current;
      }
      maybe_pop_round_robin_task(current);
    }

    LOG(debug) << "  need to reschedule";

    next = get_round_robin_task();
    if (next) {
      LOG(debug) << "Trying task " << next->tid << " from yield queue";
      if (is_task_runnable(next, by_waitpid)) {
        break;
      }
      maybe_pop_round_robin_task(next);
      continue;
    }

    if (!next) {
      next = find_next_runnable_task(current, by_waitpid, INT32_MAX);
    }

    if (next && next->priority > 0 && in_high_priority_only_interval()) {
      if (*by_waitpid) {
        LOG(debug)
            << "Waking up low-priority task with by_waitpid; not sleeping";
        // We must run this low-priority task. Fortunately it's just waking
        // up from a blocking syscall; we'll record the syscall event and then
        // (unless it was an interrupted syscall) we'll return to
        // get_next_thread, which will either run a higher priority thread
        // or (more likely) reach here again but in the !*by_waitpid case.
      } else {
        LOG(debug)
            << "Waking up low-priority task without by_waitpid; sleeping";
        sleep_time(0.1);
        continue;
      }
    }
    break;
  }

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

  if (current && current != next) {
    maybe_reset_high_priority_only_intervals();
    LOG(debug) << "Switching from " << current->tid << "(" << current->name()
               << ") to " << next->tid << "(" << next->name() << ") (priority "
               << current->priority << " to " << next->priority << ") at "
               << current->trace_writer().time();
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
  maybe_pop_round_robin_task(t);

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

Task* Scheduler::get_round_robin_task() {
  return task_round_robin_queue.empty() ? nullptr
                                        : task_round_robin_queue.front();
}

void Scheduler::maybe_pop_round_robin_task(Task* t) {
  if (task_round_robin_queue.empty() || t != task_round_robin_queue.front()) {
    return;
  }
  task_round_robin_queue.pop_front();
  t->in_round_robin_queue = false;
  task_priority_set.insert(make_pair(t->priority, t));
}
