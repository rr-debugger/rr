/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

//#define MONITOR_UNSWITCHABLE_WAITS

#include "Scheduler.h"

#include <math.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>

#include "Flags.h"
#include "RecordSession.h"
#include "RecordTask.h"
#include "core.h"
#include "log.h"

using namespace std;

namespace rr {

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
      max_ticks_(DEFAULT_MAX_TICKS),
      must_run_task(nullptr),
      pretend_num_cores_(1),
      always_switch(false),
      enable_chaos(false),
      enable_poll(false),
      last_reschedule_in_high_priority_only_interval(false) {
  regenerate_affinity_mask();
}

/**
 * Compute an affinity mask to report via sched_getaffinity.
 * This mask should include whatever CPU number the task is
 * actually running on, otherwise we may confuse applications.
 * The mask should also match the number of CPUs we're pretending
 * to have.
 */
void Scheduler::regenerate_affinity_mask() {
  int ret = sched_getaffinity(0, sizeof(pretend_affinity_mask_),
                              &pretend_affinity_mask_);
  if (ret) {
    FATAL() << "Failed sched_getaffinity";
  }

  int cpu = session.trace_writer().bound_to_cpu();
  if (cpu < 0) {
    // We only run one thread at a time but we're not limiting
    // where that thread can run, so report all available CPUs
    // in the affinity mask even though that doesn't match
    // pretend_num_cores. We only run unbound during tests or
    // when explicitly requested by the user.
    return;
  }
  if (!CPU_ISSET(cpu, &pretend_affinity_mask_)) {
    LOG(warn) << "Bound CPU " << cpu << " not in affinity mask";
    // Use the original affinity mask since something strange is
    // going on.
    return;
  }
  // Try to limit the CPU numbers we generate to the ones that
  // actually exist on this system, but generate fake ones if there
  // aren't enough.
  int faked_num_cpus = sysconf(_SC_NPROCESSORS_CONF);
  if (faked_num_cpus < pretend_num_cores_) {
    faked_num_cpus = pretend_num_cores_;
  }
  // generate random CPU numbers that fit into the CPU mask
  vector<int> other_cpus;
  for (int i = 0; i < faked_num_cpus; ++i) {
    if (i != cpu) {
      other_cpus.push_back(i);
    }
  }
  random_shuffle(other_cpus.begin(), other_cpus.end());
  CPU_ZERO(&pretend_affinity_mask_);
  CPU_SET(cpu, &pretend_affinity_mask_);
  for (int i = 0; i < pretend_num_cores_ - 1; ++i) {
    CPU_SET(other_cpus[i], &pretend_affinity_mask_);
  }
}

void Scheduler::set_enable_chaos(bool enable_chaos) {
  this->enable_chaos = enable_chaos;

  /* When chaos mode is enabled, pretend to have 1-8 cores at random, otherwise
   * return 1 to maximize throughput (since effectively we really only have
   * one core).
   */
  pretend_num_cores_ = enable_chaos ? (random() % 8 + 1) : 1;
  regenerate_affinity_mask();
}

RecordTask* Scheduler::get_next_task_with_same_priority(RecordTask* t) {
  if (!t || t->in_round_robin_queue) {
    return nullptr;
  }

  auto it = task_priority_set.find(make_pair(t->priority, t));
  DEBUG_ASSERT(it != task_priority_set.end());
  ++it;
  if (it == task_priority_set.end() || it->first != t->priority) {
    it = task_priority_set.lower_bound(make_pair(t->priority, nullptr));
  }
  return it->second;
}

static double random_frac() { return double(random() % INT32_MAX) / INT32_MAX; }

int Scheduler::choose_random_priority(RecordTask* t) {
  double prob = t->tgid() == t->tid ? main_thread_low_priority_probability
                                    : low_priority_probability;
  return random_frac() < prob;
}

static bool treat_syscall_as_nonblocking(int syscallno, SupportedArch arch) {
  return is_sched_yield_syscall(syscallno, arch) ||
         is_exit_syscall(syscallno, arch) ||
         is_exit_group_syscall(syscallno, arch);
}

/**
 * Returns true if we should return t as the runnable task. Otherwise we
 * should check the next task. Note that if this returns true get_next_thread
 * |must| return t as the runnable task, otherwise we will lose an event and
 * probably deadlock!!!
 */
bool Scheduler::is_task_runnable(RecordTask* t, bool* by_waitpid) {
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
    if (t->is_signal_pending(SIGCONT)) {
      // We have to do this here. RecordTask::signal_delivered can't always
      // do it because if we don't PTRACE_CONT the task, we'll never see the
      // SIGCONT.
      t->emulate_SIGCONT();
      // We shouldn't run any user code since there is at least one signal
      // pending.
      t->resume_execution(RESUME_SYSCALL, RESUME_WAIT, RESUME_NO_TICKS);
      *by_waitpid = true;
      must_run_task = t;
      LOG(debug) << "  Got " << t->tid
                 << " out of emulated stop due to pending SIGCONT";
      return true;
    } else {
      LOG(debug) << "  " << t->tid << " is stopped by ptrace or signal";
      // We have no way to detect a SIGCONT coming from outside the tracees.
      // We just have to poll SigPnd in /proc/<pid>/status.
      enable_poll = true;
      // We also need to check if the task got killed.
      t->try_wait();
      // N.B.: If we supported ptrace exit notifications for killed tracee's
      // that would need handling here, but we don't at the moment.
      return t->is_dying();
    }
  }

  if (EV_SYSCALL == t->ev().type() &&
      PROCESSING_SYSCALL == t->ev().Syscall().state &&
      treat_syscall_as_nonblocking(t->ev().Syscall().number, t->arch())) {
    // These syscalls never really block but the kernel may report that
    // the task is not stopped yet if we pass WNOHANG. To make them
    // behave predictably, do a blocking wait.
    t->wait();
    *by_waitpid = true;
    must_run_task = t;
    LOG(debug) << "  sched_yield ready with status " << t->status();
    return true;
  }

  LOG(debug) << "  " << t->tid << " is blocked on " << t->ev()
             << "; checking status ...";
  bool did_wait_for_t;
  did_wait_for_t = t->try_wait();
  if (did_wait_for_t) {
    *by_waitpid = true;
    must_run_task = t;
    LOG(debug) << "  ready with status " << t->status();
    return true;
  }
  LOG(debug) << "  still blocked";
  // Try next task
  return false;
}

RecordTask* Scheduler::find_next_runnable_task(RecordTask* t, bool* by_waitpid,
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
      vector<RecordTask*> tasks;
      for (auto it = same_priority_start; it != same_priority_end; ++it) {
        tasks.push_back(it->second);
      }
      random_shuffle(tasks.begin(), tasks.end());
      for (RecordTask* next : tasks) {
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
        RecordTask* next = task_iterator->second;

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
  vector<RecordTask*> tasks;
  for (auto p : task_priority_set) {
    tasks.push_back(p.second);
  }
  for (RecordTask* t : task_round_robin_queue) {
    tasks.push_back(t);
  }
  for (RecordTask* t : tasks) {
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

bool Scheduler::treat_as_high_priority(RecordTask* t) {
  return task_priority_set.size() > 1 && t->priority == 0;
}

void Scheduler::validate_scheduled_task() {
  ASSERT(current_, !must_run_task || must_run_task == current_);
  ASSERT(current_,
         task_round_robin_queue.empty() ||
             current_ == task_round_robin_queue.front());
}

Scheduler::Rescheduled Scheduler::reschedule(Switchable switchable) {
  Rescheduled result;
  result.interrupted_by_signal = false;
  result.by_waitpid = false;
  result.started_new_timeslice = false;

  LOG(debug) << "Scheduling next task";

  must_run_task = nullptr;
  enable_poll = false;

  double now = monotonic_now_sec();

  maybe_reset_priorities(now);

  if (current_ && switchable == PREVENT_SWITCH) {
    LOG(debug) << "  (" << current_->tid << " is un-switchable at "
               << current_->ev() << ")";
    if (current_->is_running()) {
      LOG(debug) << "  and running; waiting for state change";
      /* |current| is un-switchable, but already running. Wait for it to change
       * state before "scheduling it", so avoid busy-waiting with our client. */
      current_->wait(interrupt_after_elapsed_time());
#ifdef MONITOR_UNSWITCHABLE_WAITS
      double wait_duration = monotonic_now_sec() - now;
      if (wait_duration >= 0.010) {
        log_warn("Waiting for unswitchable %s took %g ms",
                 strevent(current_->event), 1000.0 * wait_duration);
      }
#endif
      result.by_waitpid = true;
      LOG(debug) << "  new status is " << current_->status();
    }
    validate_scheduled_task();
    return result;
  }

  RecordTask* next;
  while (true) {
    maybe_reset_high_priority_only_intervals(now);
    last_reschedule_in_high_priority_only_interval =
        in_high_priority_only_interval(now);

    if (current_) {
      // Determine if we should run current_ again
      RecordTask* round_robin_task = get_round_robin_task();
      if (!round_robin_task) {
        next = find_next_runnable_task(current_, &result.by_waitpid,
                                       current_->priority - 1);
        if (next) {
          // There is a runnable higher-priority task. Run it.
          break;
        }
      }
      // To run current_ again:
      // -- its timeslice must not have expired
      // -- it must be high priority if we're in a high-priority-only interval
      // -- it must be the head of the round-robin queue or the queue is empty
      // (this might not hold if it was at the head of the queue but we
      // rejected current_ and popped it in a previous iteration of this loop)
      // -- it must be runnable, and not in an unstable exit.
      if (!current_->unstable && !always_switch &&
          (!round_robin_task || round_robin_task == current_) &&
          (treat_as_high_priority(current_) ||
           !last_reschedule_in_high_priority_only_interval) &&
          current_->tick_count() < current_timeslice_end() &&
          is_task_runnable(current_, &result.by_waitpid)) {
        LOG(debug) << "  Carrying on with task " << current_->tid;
        validate_scheduled_task();
        return result;
      }
      // Having rejected current_, be prepared to run the next task in the
      // round-robin queue.
      maybe_pop_round_robin_task(current_);
    }

    LOG(debug) << "  need to reschedule";

    next = get_round_robin_task();
    if (next) {
      LOG(debug) << "Trying task " << next->tid << " from yield queue";
      if (is_task_runnable(next, &result.by_waitpid)) {
        break;
      }
      maybe_pop_round_robin_task(next);
      continue;
    }

    if (!next) {
      next = find_next_runnable_task(current_, &result.by_waitpid, INT32_MAX);
    }

    // When there's only one thread, treat it as low priority for the
    // purposes of high-priority-only-intervals. Otherwise single-threaded
    // workloads mostly don't get any chaos mode effects.
    if (next && !treat_as_high_priority(next) &&
        last_reschedule_in_high_priority_only_interval) {
      if (result.by_waitpid) {
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

    // Clear the round-robin queue since we will no longer be able to service
    // those tasks in-order.
    while (RecordTask* t = get_round_robin_task()) {
      maybe_pop_round_robin_task(t);
    }

    LOG(debug) << "  all tasks blocked or some unstable, waiting for runnable ("
               << task_priority_set.size() << " total)";

    WaitStatus status;
    do {
      int raw_status;
      if (enable_poll) {
        struct itimerval timer = { { 0, 0 }, { 1, 0 } };
        if (setitimer(ITIMER_REAL, &timer, nullptr) < 0) {
          FATAL() << "Failed to set itimer";
        }
        LOG(debug) << "  Arming one-second timer for polling";
      }
      pid_t tid = waitpid(-1, &raw_status, __WALL | WUNTRACED);
      if (enable_poll) {
        struct itimerval timer = { { 0, 0 }, { 0, 0 } };
        if (setitimer(ITIMER_REAL, &timer, nullptr) < 0) {
          FATAL() << "Failed to set itimer";
        }
        LOG(debug) << "  Disarming one-second timer for polling";
      }
      status = WaitStatus(raw_status);
      now = -1; // invalid, don't use
      if (-1 == tid) {
        if (EINTR == errno) {
          LOG(debug) << "  waitpid(-1) interrupted";
          ASSERT(current_, !must_run_task);
          result.interrupted_by_signal = true;
          return result;
        }
        FATAL() << "Failed to waitpid()";
      }
      LOG(debug) << "  " << tid << " changed status to " << status;

      next = session.find_task(tid);
      if (status.ptrace_event() == PTRACE_EVENT_EXEC) {
        if (next) {
          // Other threads may have unexpectedly died, in which case this
          // will be marked as unstable even though it's actually not. There's
          // no way to know until we see the EXEC event that we weren't really
          // in an unstable exit.
          next->unstable = false;
        } else {
          // The thread-group-leader died and now the exec'ing thread has
          // changed its thread ID to be thread-group leader.
          next = session.revive_task_for_exec(tid);
        }
      }
      if (!next) {
        LOG(debug) << "    ... but it's dead";
      }
    } while (!next);
    ASSERT(next,
           next->unstable || next->may_be_blocked() ||
               status.ptrace_event() == PTRACE_EVENT_EXIT)
        << "Scheduled task should have been blocked or unstable";
    next->did_waitpid(status);
    result.by_waitpid = true;
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
  validate_scheduled_task();
  setup_new_timeslice();
  result.started_new_timeslice = true;
  return result;
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

void Scheduler::on_create(RecordTask* t) {
  DEBUG_ASSERT(!t->in_round_robin_queue);
  if (enable_chaos) {
    // new tasks get a random priority
    t->priority = choose_random_priority(t);
  }
  task_priority_set.insert(make_pair(t->priority, t));
}

void Scheduler::on_destroy(RecordTask* t) {
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

void Scheduler::update_task_priority(RecordTask* t, int value) {
  if (!enable_chaos) {
    update_task_priority_internal(t, value);
  }
}

void Scheduler::in_stable_exit(RecordTask* t) {
  update_task_priority_internal(t, t->priority);
}

void Scheduler::update_task_priority_internal(RecordTask* t, int value) {
  if (t->stable_exit && !enable_chaos) {
    // Tasks in a stable exit have the highest priority. We should force them
    // to complete exiting ASAP to clean up resources. They may not be runnable
    // due to waiting for PTRACE_EVENT_EXIT to complete.
    value = -9999;
  }
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

void Scheduler::schedule_one_round_robin(RecordTask* t) {
  LOG(debug) << "Scheduling round-robin because of task " << t->tid;

  ASSERT(t, t == current_);
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

RecordTask* Scheduler::get_round_robin_task() {
  return task_round_robin_queue.empty() ? nullptr
                                        : task_round_robin_queue.front();
}

void Scheduler::maybe_pop_round_robin_task(RecordTask* t) {
  if (task_round_robin_queue.empty() || t != task_round_robin_queue.front()) {
    return;
  }
  task_round_robin_queue.pop_front();
  t->in_round_robin_queue = false;
  task_priority_set.insert(make_pair(t->priority, t));
}

} // namespace rr
