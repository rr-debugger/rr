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

// Probability of making a thread low priority. Keep this reasonably low
// because the goal is to victimize some specific threads
static double low_priority_probability = 0.1;
// Give main threads a higher probability of being low priority because
// many tests are basically main-thread-only
static double main_thread_low_priority_probability = 0.3;
static double very_short_timeslice_probability = 0.1;
static Ticks very_short_timeslice_max_duration = 100;
static double short_timeslice_probability = 0.1;
static Ticks short_timeslice_max_duration = 10000;
// Time between priority refreshes is uniformly distributed from 0 to 20s
static double priorities_refresh_max_interval = 20;

/*
 * High-Priority-Only Intervals
 *
 * We assume that for a test failure we want to reproduce, we will reproduce a
 * failure if we completely avoid scheduling a certain thread for a period of
 * D seconds, where the start of that period must fall between S and S+T
 * seconds since the start of the test. All these constants are unknown to
 * rr, but we assume 1ms <= D <= 2s.
 *
 * Since we only need to reproduce any particular bug once, it would be best
 * to have roughly similar probabilities for reproducing each bug given its
 * unknown parameters. It's unclear what is the optimal approach here, but
 * here's ours:
 *
 * First we have to pick the right thread to treat as low priority --- without
 * making many other threads low priority, since they might need to run while
 * our victim thread is being starved. So we give each thread a 0.1 probability
 * of being low priority, except for the main thread which we make 0.3, since
 * starving the main thread is often very interesting.
 * Then we guess a value D' for D. We uniformly choose between 1ms, 2ms, 4ms,
 * 8ms, ..., 1s, 2s. Out of these 12 possibilities, one is between D and 2xD.
 * We adopt the goal of high-priority-only intervals consume at most 20% of
 * running time. Then to maximise the probability of triggering the test
 * failure, we start high-priority-only intervals as often as possible,
 * i.e. one for D' seconds starting every 5xD' seconds.
 * The start time of the first interval is chosen uniformly randomly to be
 * between 0 and 4xD'.
 * Then, if we guessed D' and the low-priority thread correctly, the
 * probability of triggering the test failure is 1 if T >= 4xD', T/4xD'
 * otherwise, i.e. >= T/8xD. (Higher values of D' than optimal can also trigger
 * failures, but at reduced probabilities since we can schedule them less
 * often.)
 */
static double min_high_priority_only_duration = 0.001;
static int high_priority_only_duration_steps = 12;
static double high_priority_only_duration_step_factor = 2;
// Allow this much of overall runtime to be in the "high priority only" interval
static double high_priority_only_fraction = 0.2;

Scheduler::Scheduler(RecordSession& session)
    : session(session),
      current_(nullptr),
      current_timeslice_end_(0),
      high_priority_only_intervals_refresh_time(0),
      high_priority_only_intervals_start(0),
      high_priority_only_intervals_duration(0),
      high_priority_only_intervals_period(0),
      priorities_refresh_time(0),
      pretend_num_cores_(1),
      max_ticks_(DEFAULT_MAX_TICKS),
      always_switch(false),
      enable_chaos(false),
      last_reschedule_in_high_priority_only_interval(false),
      must_run_task(nullptr) {}

void Scheduler::set_enable_chaos(bool enable_chaos) {
  this->enable_chaos = enable_chaos;

  /* When chaos mode is enabled, pretend to have 1-8 cores at random, otherwise
   * return 1 to maximize throughput (since effectively we really only have
   * one core).
   */
  pretend_num_cores_ = enable_chaos ? (random() % 8 + 1) : 1;
}

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

static double random_frac() { return double(random() % INT32_MAX) / INT32_MAX; }

int Scheduler::choose_random_priority(Task* t) {
  double prob = t->tgid() == t->tid ? main_thread_low_priority_probability
                                    : low_priority_probability;
  return random_frac() < prob;
}

/**
 * Returns true if we should return t as the runnable task. Otherwise we
 * should check the next task. Note that if this returns true get_next_thread
 * |must| return t as the runnable task, otherwise we will lose an event and
 * probably deadlock!!!
 */
bool Scheduler::is_task_runnable(Task* t, bool* by_waitpid) {
  ASSERT(t, !must_run_task) << "is_task_runnable called again after it "
                               "returned a task that must run!";

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
    *by_waitpid = true;
    must_run_task = t;
    LOG(debug) << "  sched_yield ready with status " << HEX(t->status());
    return true;
  }

  LOG(debug) << "  " << t->tid << " is blocked on " << t->ev()
             << "; checking status ...";
  bool did_wait_for_t;
  did_wait_for_t = t->try_wait();
  if (did_wait_for_t) {
    *by_waitpid = true;
    must_run_task = t;
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

void Scheduler::setup_new_timeslice() {
  Ticks max_timeslice_duration = max_ticks_;
  if (enable_chaos) {
    // Hypothesis: some bugs require short timeslices to expose. But we don't
    // want the average timeslice to be too small. So make 10% of timeslices
    // very short, 10% short-ish, and the rest uniformly distributed between 0
    // and |max_ticks_|.
    double timeslice_kind_frac = random_frac();
    if (timeslice_kind_frac < very_short_timeslice_probability) {
      max_timeslice_duration = very_short_timeslice_max_duration;
    } else if (timeslice_kind_frac <
               very_short_timeslice_probability + short_timeslice_probability) {
      max_timeslice_duration = short_timeslice_max_duration;
    } else {
      max_timeslice_duration = max_ticks_;
    }
  }
  current_timeslice_end_ = current_->tick_count() +
                           (random() % min(max_ticks_, max_timeslice_duration));
  current_->registers_at_start_of_uninterrupted_timeslice =
      unique_ptr<Registers>(new Registers(current_->regs()));
}

static void sleep_time(double t) {
  struct timespec ts;
  ts.tv_sec = (time_t)floor(t);
  ts.tv_nsec = (long)((t - ts.tv_sec) * 1e9);
  nanosleep(&ts, NULL);
}

void Scheduler::maybe_reset_priorities(double now) {
  if (!enable_chaos || priorities_refresh_time > now) {
    return;
  }
  // Reset task priorities again at some point in the future.
  priorities_refresh_time =
      now + random_frac() * priorities_refresh_max_interval;
  vector<Task*> tasks;
  for (auto p : task_priority_set) {
    tasks.push_back(p.second);
  }
  for (Task* t : task_round_robin_queue) {
    tasks.push_back(t);
  }
  for (Task* t : tasks) {
    update_task_priority_internal(t, choose_random_priority(t));
  }
}

void Scheduler::maybe_reset_high_priority_only_intervals(double now) {
  if (!enable_chaos || high_priority_only_intervals_refresh_time > now) {
    return;
  }
  int duration_step = random() % high_priority_only_duration_steps;
  high_priority_only_intervals_duration =
      min_high_priority_only_duration *
      pow(high_priority_only_duration_step_factor, duration_step);
  high_priority_only_intervals_period =
      high_priority_only_intervals_duration / high_priority_only_fraction;
  high_priority_only_intervals_start =
      now +
      random_frac() * (high_priority_only_intervals_period -
                       high_priority_only_intervals_duration);
  high_priority_only_intervals_refresh_time =
      now +
      min_high_priority_only_duration *
          pow(high_priority_only_duration_step_factor,
              high_priority_only_duration_steps - 1) /
          high_priority_only_fraction;
}

bool Scheduler::in_high_priority_only_interval(double now) {
  if (now < high_priority_only_intervals_start) {
    return false;
  }
  double mod = fmod(now - high_priority_only_intervals_start,
                    high_priority_only_intervals_period);
  return mod < high_priority_only_intervals_duration;
}

bool Scheduler::treat_as_high_priority(Task* t) {
  return task_priority_set.size() > 1 && t->priority == 0;
}

bool Scheduler::reschedule(Switchable switchable, bool* by_waitpid) {
  LOG(debug) << "Scheduling next task";

  *by_waitpid = false;
  must_run_task = nullptr;

  double now = monotonic_now_sec();

  maybe_reset_priorities(now);

  if (current_ && switchable == PREVENT_SWITCH) {
    LOG(debug) << "  (" << current_->tid << " is un-switchable at "
               << current_->ev() << ")";
    if (current_->is_running()) {
      LOG(debug) << "  and running; waiting for state change";
      /* |current| is un-switchable, but already running. Wait for it to change
       * state
       * before "scheduling it", so avoid busy-waiting with our client. */
      current_->wait(interrupt_after_elapsed_time());
#ifdef MONITOR_UNSWITCHABLE_WAITS
      double wait_duration = monotonic_now_sec() - now;
      if (wait_duration >= 0.010) {
        log_warn("Waiting for unswitchable %s took %g ms",
                 strevent(current_->event), 1000.0 * wait_duration);
      }
#endif
      *by_waitpid = true;
      LOG(debug) << "  new status is " << HEX(current_->status());
    }
    return true;
  }

  Task* next;
  while (true) {
    maybe_reset_high_priority_only_intervals(now);
    last_reschedule_in_high_priority_only_interval =
        in_high_priority_only_interval(now);

    if (current_) {
      next = get_round_robin_task()
                 ? nullptr
                 : find_next_runnable_task(current_, by_waitpid,
                                           current_->priority - 1);
      if (next) {
        break;
      }
      if (!current_->unstable && !always_switch &&
          (treat_as_high_priority(current_) ||
           !last_reschedule_in_high_priority_only_interval) &&
          current_->tick_count() < current_timeslice_end() &&
          is_task_runnable(current_, by_waitpid)) {
        LOG(debug) << "  Carrying on with task " << current_->tid;
        ASSERT(current_, !must_run_task || must_run_task == current_);
        return true;
      }
      maybe_pop_round_robin_task(current_);
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
      next = find_next_runnable_task(current_, by_waitpid, INT32_MAX);
    }

    // When there's only one thread, treat it as low priority for the
    // purposes of high-priority-only-intervals. Otherwise single-threaded
    // workloads mostly don't get any chaos mode effects.
    if (next && !treat_as_high_priority(next) &&
        last_reschedule_in_high_priority_only_interval) {
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
        sleep_time(0.001);
        now = monotonic_now_sec();
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
      now = -1; // invalid, don't use
      if (-1 == tid) {
        if (EINTR == errno) {
          LOG(debug) << "  waitpid(-1) interrupted";
          ASSERT(current_, !must_run_task);
          return false;
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
    must_run_task = next;
  }

  if (current_ && current_ != next) {
    LOG(debug) << "Switching from " << current_->tid << "(" << current_->name()
               << ") to " << next->tid << "(" << next->name() << ") (priority "
               << current_->priority << " to " << next->priority << ") at "
               << current_->trace_writer().time();
  }

  maybe_reset_high_priority_only_intervals(now);
  current_ = next;
  ASSERT(current_, !must_run_task || must_run_task == current_);
  setup_new_timeslice();
  return true;
}

double Scheduler::interrupt_after_elapsed_time() const {
  // Where does the 3 seconds come from?  No especially
  // good reason.  We want this to be pretty high,
  // because it's a last-ditch recovery mechanism, not a
  // primary thread scheduler.  Though in theory the
  // PTRACE_INTERRUPT's shouldn't interfere with other
  // events, that's hard to test thoroughly so try to
  // avoid it.
  double delay = 3;
  if (enable_chaos) {
    double now = monotonic_now_sec();
    if (high_priority_only_intervals_start) {
      double next_interval_start =
          (floor((now - high_priority_only_intervals_start) /
                 high_priority_only_intervals_period) +
           1) *
              high_priority_only_intervals_period +
          high_priority_only_intervals_start;
      delay = min(delay, next_interval_start - now);
    }
    if (high_priority_only_intervals_refresh_time) {
      delay = min(delay, high_priority_only_intervals_refresh_time - now);
    }
    if (priorities_refresh_time) {
      delay = min(delay, priorities_refresh_time - now);
    }
  }
  return max(0.001, delay);
}

void Scheduler::on_create(Task* t) {
  assert(!t->in_round_robin_queue);
  if (enable_chaos) {
    // new tasks get a random priority
    t->priority = choose_random_priority(t);
  }
  task_priority_set.insert(make_pair(t->priority, t));
}

void Scheduler::on_destroy(Task* t) {
  if (t == current_) {
    current_ = nullptr;
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
  expire_timeslice();
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
