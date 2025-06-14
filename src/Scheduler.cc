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

#include "CPUs.h"
#include "Flags.h"
#include "RecordSession.h"
#include "RecordTask.h"
#include "TraceeAttentionSet.h"
#include "WaitManager.h"
#include "core.h"
#include "log.h"

using namespace std;

namespace rr {

FILE_CACHE_LOG_MODULE();

// Probability of making a thread low priority. Keep this reasonably low
// because the goal is to victimize some specific threads
static double low_priority_probability = 0.1;
// Give main threads a higher probability of being low priority because
// many tests are basically main-thread-only
static double main_thread_low_priority_probability = 0.3;
static double very_short_timeslice_probability = 0.1;
// For low priority tasks, assign some probability of being treated
// as medium priority until their first yield.
// This lets a low priority task run until it unblocks the execution of
// a high-priority task and then never run again during a
// high-priority-only interval. See the `startup` test.
static double postpone_low_priority_until_after_yield = 0.2;
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
 * The start time of the first interval is chosen to be between 0 and 4xD'.
 * To make sure we capture startup effects, we choose 0 with probability 0.25
 * and uniformly between 0 and 4xD' otherwise.
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
static double start_high_priority_only_immediately_probability = 0.25;

Scheduler::Scheduler(RecordSession& session)
    : reschedule_count(0),
      session(session),
      task_priority_set_total_count(0),
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
      in_exec_tgid(0),
      ntasks_stopped(0),
      always_switch(false),
      enable_chaos(false),
      enable_poll(false),
      last_reschedule_in_high_priority_only_interval(false),
      unlimited_ticks_mode(false) {
  std::random_device rd;
  random.seed(rd());
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
  int cpu = session.trace_writer().bound_to_cpu();
  if (cpu < 0) {
    // We only run one thread at a time but we're not limiting
    // where that thread can run, so report all available CPUs
    // in the affinity mask even though that doesn't match
    // pretend_num_cores. We only run unbound during tests or
    // when explicitly requested by the user.
    return;
  }
  auto initial_affinity = CPUs::get().initial_affinity();
  if (find(initial_affinity.begin(), initial_affinity.end(), cpu)
      == initial_affinity.end()) {
    LOGM(warn) << "Bound CPU " << cpu << " not in affinity mask";
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
  shuffle(other_cpus.begin(), other_cpus.end(), random);
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

void Scheduler::set_num_cores(int cores) {
  pretend_num_cores_ = cores;
  regenerate_affinity_mask();
}

static double random_frac() { return double(random() % INT32_MAX) / INT32_MAX; }

static const int CHAOS_MODE_HIGH_PRIORITY = 0;
static const int CHAOS_MODE_MEDIUM_PRIORITY_UNTIL_NEXT_YIELD = 1;
static const int CHAOS_MODE_LOW_PRIORITY = 2;

int Scheduler::choose_random_priority(RecordTask* t) {
  double prob = t->tgid() == t->tid ? main_thread_low_priority_probability
                                    : low_priority_probability;
  if (random_frac() < prob) {
    if (random_frac() < postpone_low_priority_until_after_yield) {
      return CHAOS_MODE_MEDIUM_PRIORITY_UNTIL_NEXT_YIELD;
    }
    return CHAOS_MODE_LOW_PRIORITY;
  }
  return CHAOS_MODE_HIGH_PRIORITY;
}

static bool treat_syscall_as_nonblocking(int syscallno, SupportedArch arch) {
  return is_sched_yield_syscall(syscallno, arch) ||
         is_exit_syscall(syscallno, arch) ||
         is_exit_group_syscall(syscallno, arch);
}

class WaitAggregator {
public:
  explicit WaitAggregator(int num_waits_before_polling_stops) :
    num_waits_before_polling_stops(num_waits_before_polling_stops),
    did_poll_stops(false) {}
  bool try_wait(RecordTask* t);
  // Return a list of tasks that we should check for unexpected exits.
  const vector<RecordTask*>& exit_candidates() { return exit_candidates_; }
  static bool try_wait_exit(RecordTask* t);
private:
  int num_waits_before_polling_stops;
  // We defer making an actual wait syscall until we really need to.
  // This records whether poll_stops has been called already.
  bool did_poll_stops;
  vector<RecordTask*> exit_candidates_;
};

bool WaitAggregator::try_wait(RecordTask* t) {
  if (!did_poll_stops) {
    if (num_waits_before_polling_stops > 0) {
      --num_waits_before_polling_stops;
    } else {
      WaitManager::poll_stops();
      did_poll_stops = true;
    }
  }

  // Check if there is a status change for us.
  WaitOptions options(t->tid);
  // Rely on already-polled stops if we have them (don't do another syscall)
  options.can_perform_syscall = !did_poll_stops;
  options.block_seconds = 0;
  WaitResult result = WaitManager::wait_stop(options);
  if (result.code != WAIT_OK) {
    exit_candidates_.push_back(t);
    return false;
  }
  LOGM(debug) << "wait on " << t->tid << " returns " << result.status;
  // If did_waitpid fails then the task left the stop prematurely
  // due to SIGKILL or equivalent, and we should report that we did not get
  // a stop.
  return t->did_waitpid(result.status);
}

bool WaitAggregator::try_wait_exit(RecordTask* t) {
  WaitOptions options(t->tid);
  options.block_seconds = 0;
  // Either we died/are dying unexpectedly, or we were in exec and changed the tid,
  // or we're not dying at all.
  // Try to differentiate the first two situations by seeing if there is an exit
  // notification ready for us to de-queue, in which case we synthesize an
  // exit event (but don't actually reap the task, instead leaving that
  // for the generic cleanup code).
  options.consume = false;
  WaitResult result = WaitManager::wait_exit(options);
  switch (result.code) {
    case WAIT_OK: {
      bool ok = t->did_waitpid(result.status);
      ASSERT(t, ok) << "did_waitpid shouldn't fail for exit statuses";
      return true;
    }
    case WAIT_NO_STATUS:
      // This can happen when the task is in zap_pid_ns_processes waiting for all tasks
      // in the pid-namespace to exit. It's not in a signal stop, but it's also not
      // ready to be reaped yet, yet we're still tracing it. Don't wait on this
      // task, we should be able to reap it later.
      // But most likely this task is just still blocked.
      return false;
    case WAIT_NO_CHILD:
    default:
      return false;
  }
}

/**
 * Returns true if we should return t as the runnable task. Otherwise we
 * should check the next task. Note that if this returns true get_next_thread
 * |must| return t as the runnable task, otherwise we will lose an event and
 * probably deadlock!!!
 */
bool Scheduler::is_task_runnable(RecordTask* t, WaitAggregator& wait_aggregator, bool* by_waitpid) {
  ASSERT(t, !must_run_task) << "is_task_runnable called again after it "
                               "returned a task that must run!";

  if (t->detached_proxy) {
    LOGM(debug) << "  " << t->tid << " is a detached proxy";
    return false;
  }

  if (t->waiting_for_reap) {
    if (t->may_reap()) {
      LOGM(debug) << "  " << t->tid << " is waiting to be reaped, and can be reaped";
      return true;
    }
    LOGM(debug) << "  " << t->tid << " is waiting to be reaped, but can't be reaped yet";
    return false;
  }

  LOGM(debug) << "Task event is " << t->ev();
  if (!t->may_be_blocked() && (t->is_stopped() || t->was_reaped())) {
    LOGM(debug) << "  " << t->tid << " isn't blocked";
    if (t->schedule_frozen) {
      LOGM(debug) << "  " << t->tid << "  but is frozen";
      return false;
    }
    return true;
  }

  if (t->emulated_stop_type != NOT_STOPPED) {
    if (t->is_stopped() && t->is_signal_pending(SIGCONT)) {
      // We have to do this here. RecordTask::signal_delivered can't do it
      // in the case where t->is_stopped(), because if we don't PTRACE_CONT
      // the task, we'll never see the SIGCONT.
      t->emulate_SIGCONT();
      // We shouldn't run any user code since there is at least one signal
      // pending.
      if (t->resume_execution(RESUME_SYSCALL, RESUME_WAIT_NO_EXIT, RESUME_NO_TICKS)) {
        *by_waitpid = true;
        must_run_task = t;
        LOGM(debug) << "  Got " << t->tid
                   << " out of emulated stop due to pending SIGCONT";
        return true;
      }
      // Tracee exited unexpectedly. Reexamine it now in case it has a new
      // status we can use. Note that we cleared `t->emulated_stop_type`
      // so we won't end up here again.
      return is_task_runnable(t, wait_aggregator, by_waitpid);
    } else {
      LOGM(debug) << "  " << t->tid << " is stopped by ptrace or signal";
      // We have no way to detect a SIGCONT coming from outside the tracees.
      // We just have to poll SigPnd in /proc/<pid>/status.
      enable_poll = true;
      // We also need to check if the task got killed.
      WaitAggregator::try_wait_exit(t);
      // N.B.: If we supported ptrace exit notifications for killed tracee's
      // that would need handling here, but we don't at the moment.
      if (t->seen_ptrace_exit_event()) {
        LOGM(debug) << "  ... but it died";
        return true;
      }
      if (t->is_stopped()) {
        return false;
      }
      // If we're not stopped, we need to get to the stop.
      // AFAIK we can only get here with group stops, which are eagerly applied
      // to every task in the group. If I'm wrong, die here.
      ASSERT(t, t->emulated_stop_type == GROUP_STOP);
      LOGM(debug) << "  interrupting and waiting";
      t->do_ptrace_interrupt();
      // Wait on the task to get the kernel to kick it into the group stop.
      // If it died, we can deal with it later.
      return t->wait();
    }
  }

  if (t->seen_ptrace_exit_event() && !t->handled_ptrace_exit_event()) {
    LOGM(debug) << "  " << t->tid << " has a pending PTRACE_EVENT_EXIT to process; we can run it";
    return true;
  } else if (t->waiting_for_ptrace_exit && !t->was_reaped()) {
    LOGM(debug) << "  " << t->tid << " is waiting to exit; checking status ...";
  } else if (t->is_stopped() || t->was_reaped()) {
    LOGM(debug) << "  " << t->tid << "  was already stopped with status " << t->status();
    if (t->schedule_frozen && t->status().ptrace_event() != PTRACE_EVENT_SECCOMP) {
      LOGM(debug) << "   but is frozen";
      return false;
    }
    // If we have may_be_blocked, but we aren't running, then somebody noticed
    // this event earlier and already called did_waitpid for us. Just pretend
    // we did that here.
    *by_waitpid = true;
    must_run_task = t;
    return true;
  } else if (EV_SYSCALL == t->ev().type() &&
      PROCESSING_SYSCALL == t->ev().Syscall().state &&
      treat_syscall_as_nonblocking(t->ev().Syscall().number, t->arch())) {
    if (t->schedule_frozen) {
      LOGM(debug) << "  " << t->tid << " is frozen in sched_yield";
      return false;
    }
    // These syscalls never really block but the kernel may report that
    // the task is not stopped yet if we pass WNOHANG. To make them
    // behave predictably, do a blocking wait.
    if (!t->wait()) {
      // Task got SIGKILL or equivalent while trying to process the stop.
      // Ignore this event and we'll process the new status later.
      return false;
    }
    *by_waitpid = true;
    must_run_task = t;
    LOGM(debug) << "  " << syscall_name(t->ev().Syscall().number, t->arch())
      << " ready with status " << t->status();
    return true;
  } else {
    LOGM(debug) << "  " << t->tid << " is blocked on " << t->ev()
              << "; checking status ...";
  }

  bool did_wait_for_t;
  did_wait_for_t = wait_aggregator.try_wait(t);
  if (did_wait_for_t) {
    LOGM(debug) << "  ready with status " << t->status();
    if (t->schedule_frozen && t->status().ptrace_event() != PTRACE_EVENT_SECCOMP) {
      LOGM(debug) << "   but is frozen";
      return false;
    }
    *by_waitpid = true;
    must_run_task = t;
    return true;
  }
  LOGM(debug) << "  still blocked";
  // Try next task
  return false;
}

RecordTask* Scheduler::find_next_runnable_task(WaitAggregator& wait_aggregator,
                                               map<int, vector<RecordTask*>>& attention_set_by_priority,
                                               bool* by_waitpid, int priority_threshold) {
  *by_waitpid = false;

  // The outer loop has one iteration per unique priority value.
  // The inner loop iterates over all tasks with that priority.
  for (auto& task_priority_set_entry : task_priority_set) {
    int priority = task_priority_set_entry.first;
    if (priority > priority_threshold) {
      return nullptr;
    }

    SamePriorityTasks& same_priority_tasks = task_priority_set_entry.second;
    if (enable_chaos) {
      vector<RecordTask*> tasks;
      for (RecordTask* t : same_priority_tasks.tasks) {
        tasks.push_back(t);
      }
      shuffle(tasks.begin(), tasks.end(), random);
      for (RecordTask* next : tasks) {
        if (is_task_runnable(next, wait_aggregator, by_waitpid)) {
          return next;
        }
      }
    } else {
      if (same_priority_tasks.consecutive_uses_of_attention_set < 20) {
        ++same_priority_tasks.consecutive_uses_of_attention_set;
        vector<RecordTask*>& attention_set = attention_set_by_priority[priority];
        sort(attention_set.begin(), attention_set.end(),
            [](RecordTask* a, RecordTask* b) -> bool {
              return a->scheduler_token < b->scheduler_token;
            });
        for (RecordTask* t : attention_set) {
          if (is_task_runnable(t, wait_aggregator, by_waitpid)) {
            return t;
          }
        }
      }
      same_priority_tasks.consecutive_uses_of_attention_set = 0;

      // Every time we schedule a new task we put it last on the list.
      // Thus starting from the beginning essentially gives us round-robin
      // behavior at each task priority level.
      for (RecordTask* t : same_priority_tasks.tasks) {
        if (is_task_runnable(t, wait_aggregator, by_waitpid)) {
          return t;
        }
      }
    }
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

void Scheduler::maybe_reset_priorities(double now) {
  if (!enable_chaos || priorities_refresh_time > now) {
    return;
  }
  // Reset task priorities again at some point in the future.
  priorities_refresh_time =
      now + random_frac() * priorities_refresh_max_interval;
  vector<RecordTask*> tasks;
  for (auto p : task_priority_set) {
    for (RecordTask* t : p.second.tasks) {
      tasks.push_back(t);
    }
  }
  for (RecordTask* t : task_round_robin_queue) {
    tasks.push_back(t);
  }
  for (RecordTask* t : tasks) {
    update_task_priority_internal(t, choose_random_priority(t));
  }
}

void Scheduler::notify_descheduled(RecordTask* t) {
  if (!enable_chaos || t->priority != CHAOS_MODE_MEDIUM_PRIORITY_UNTIL_NEXT_YIELD) {
    return;
  }
  LOGM(debug) << "Lowering priority of " << t->tid << " after descheduling";
  update_task_priority_internal(t, CHAOS_MODE_LOW_PRIORITY);
}

void Scheduler::maybe_reset_high_priority_only_intervals(double now) {
  if (!enable_chaos || high_priority_only_intervals_refresh_time > now) {
    return;
  }
  int duration_step = 11;
  high_priority_only_intervals_duration =
      min_high_priority_only_duration *
      pow(high_priority_only_duration_step_factor, duration_step);
  high_priority_only_intervals_period =
      high_priority_only_intervals_duration / high_priority_only_fraction;
  high_priority_only_intervals_start = now;
  if (random_frac() >= start_high_priority_only_immediately_probability) {
    high_priority_only_intervals_start +=
        random_frac() * (high_priority_only_intervals_period -
                         high_priority_only_intervals_duration);
  }
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
  return t->priority < CHAOS_MODE_LOW_PRIORITY;
}

void Scheduler::validate_scheduled_task() {
  ASSERT(current_, !must_run_task || must_run_task == current_);
  ASSERT(current_,
         task_round_robin_queue.empty() ||
             current_ == task_round_robin_queue.front());
}

/**
 * Wait for any tracee to change state, returning that tracee's `tid` and
 * `status` in the corresponding arguments. Optionally a maximum wait time
 * may be specified in `timeout`. Returns true if the wait was successful
 * and `tid` and `status` are valid, or false if the wait was interrupted
 * (by timeout or some other signal).
 */
static WaitResultCode wait_any(pid_t& tid, WaitStatus& status, double timeout) {
  WaitOptions options;
  if (timeout > 0) {
    options.block_seconds = timeout;
  }
  WaitResult result = WaitManager::wait_stop_or_exit(options);
  switch (result.code) {
    case WAIT_OK:
      tid = result.tid;
      status = result.status;
      break;
    case WAIT_NO_STATUS:
      LOGM(debug) << "  wait interrupted";
      break;
    case WAIT_NO_CHILD:
      LOGM(debug) << "  no child to wait for";
      break;
    default:
      FATAL() << "Unknown result code";
      break;
  }
  return result.code;
}

/**
 * Look up the task in `session` that currently has thread id `tid`, handling
 * a few corner cases like a thread execing and changing id and a thread
 * that previously detached. Returns null if task that was waited for is not
 * managed by the current session (e.g. it is dead or was previously detached).
 */
static RecordTask* find_waited_task(RecordSession& session, pid_t tid, WaitStatus status)
{
  RecordTask* waited = session.find_task(tid);
  if (status.ptrace_event() == PTRACE_EVENT_EXEC) {
    if (waited && waited->waiting_for_reap) {
      // We didn't reap this task yet but it's being replaced anyway. Get rid of it
      // so we can replace it.
      delete waited;
      waited = nullptr;
    }
    if (!waited) {
      // The thread-group-leader died and now the exec'ing thread has
      // changed its thread ID to be thread-group leader.
      waited = session.revive_task_for_exec(tid);
    }
  }

  if (!waited) {
    // See if this is one of our detached proxies' original tids.
    waited = session.find_detached_proxy_task(tid);
    if (!waited) {
      LOGM(debug) << "    ... but it's dead";
      return nullptr;
    }

    ASSERT(waited, waited->detached_proxy);
    LOGM(debug) << "    ... but it's a detached proxy";
    switch (status.type()) {
      case WaitStatus::PTRACE_EVENT:
        if (status.ptrace_event() == PTRACE_EVENT_EXIT) {
          // Proxy was killed, perhaps via SIGKILL.
          // Forward that to the real task.
          ::kill(waited->rec_tid, SIGKILL);
          LOGM(debug) << "        ... sending SIGKILL to detached process " << waited->rec_tid;;
        } else {
          ASSERT(waited, false) << "Unexpected proxy ptrace event " << status;
        }
        break;
      case WaitStatus::SIGNAL_STOP:
        // forward the signal to the real task, don't deliver it to the proxy.
        ::kill(waited->rec_tid, status.stop_sig());
        LOGM(debug) << "        ... sending " << signal_name(status.stop_sig()) <<
          " to detached process " << waited->rec_tid;;
        break;
      default:
        ASSERT(waited, false) << "Unexpected proxy event " << status;
        break;
    }
    return nullptr;
  }

  if (waited->detached_proxy) {
    if (!waited->did_waitpid(status)) {
      // Proxy died unexpectedly during the waitpid, just ignore
      // the stop.
      return nullptr;
    }
    pid_t parent_rec_tid = waited->get_parent_pid();
    LOGM(debug) << "    ... but it's a detached process.";
    RecordTask *parent = session.find_task(parent_rec_tid);
    if (parent && !waited->emulated_stop_pending) {
      LOGM(debug) << "    ... notifying parent.";
      waited->emulated_stop_type = CHILD_STOP;
      waited->emulated_stop_pending = true;
      waited->emulated_SIGCHLD_pending = true;
      waited->emulated_stop_code = status;
      parent->send_synthetic_SIGCHLD_if_necessary();
    }
    if (status.type() == WaitStatus::EXIT || status.type() == WaitStatus::FATAL_SIGNAL) {
      if (waited->thread_group()->tgid == waited->tid) {
        waited->thread_group()->exit_status = status;
      }
      if (!parent) {
        // The task is now dead, but so is our parent, so none of our
        // tasks care about this. We can now delete the proxy task.
        // This will also reap the rec_tid of the proxy task.
        delete waited;
        // If there is a parent, we'll kill this task when the parent reaps it
        // in our wait() emulation.
      }
    }

    return nullptr;
  }
  return waited;
}

bool Scheduler::may_use_unlimited_ticks() {
  return ntasks_stopped == 1 && !enable_chaos;
}

void Scheduler::started_task(RecordTask* t) {
  LOGM(debug) << "Starting " << t->tid;
  if (may_use_unlimited_ticks()) {
    unlimited_ticks_mode = true;
  }
  --ntasks_stopped;
  ASSERT(t, ntasks_stopped >= 0);
}

void Scheduler::stopped_task(RecordTask* t) {
  LOGM(debug) << "Stopping " << t->tid;
  ++ntasks_stopped;
  // When a task is created/cloned it temporarily can be stopped
  // but not in our task set.
  ASSERT(t, ntasks_stopped <= static_cast<int>(session.tasks().size()) + 1);
}

Scheduler::Rescheduled Scheduler::reschedule(Switchable switchable) {
  Rescheduled result;
  result.interrupted_by_signal = false;
  result.by_waitpid = false;
  result.started_new_timeslice = false;

  LOGM(debug) << "Scheduling next task (" <<
    ((switchable == PREVENT_SWITCH) ? "PREVENT_SWITCH)" : "ALLOW_SWITCH)");

  must_run_task = nullptr;
  enable_poll = false;

  double now = monotonic_now_sec();
  double timeout = interrupt_after_elapsed_time();

  maybe_reset_priorities(now);

  if (current_ && switchable == PREVENT_SWITCH) {
    LOGM(debug) << "  (" << current_->tid << " is un-switchable at "
               << current_->ev() << ")";
    if (!current_->is_stopped()) {
      /* |current| is un-switchable, but already running. Wait for it to change
      * state before "scheduling it", so avoid busy-waiting with our client. */
      LOGM(debug) << "  and running; waiting for state change";
      while (true) {
        if (unlimited_ticks_mode) {
          LOGM(debug) << "Using unlimited ticks mode";
          // Unlimited ticks mode means that there is only one non-blocked task.
          // We run it without a timeslice to avoid unnecessary switches to the
          // tracer. However, this does mean we need to be on the look out for
          // other tasks becoming runnable, which we usually check on timeslice
          // expiration.
          ASSERT(current_, !ntasks_stopped);
          pid_t tid;
          WaitStatus status;
          WaitResultCode wait_result = wait_any(tid, status, -1);
          if (wait_result == WAIT_NO_STATUS) {
            ASSERT(current_, !must_run_task);
            result.interrupted_by_signal = true;
            return result;
          }
          ASSERT(current_, wait_result == WAIT_OK);
          RecordTask *waited = find_waited_task(session, tid, status);
          if (!waited) {
            continue;
          }
          if (!waited->did_waitpid(status)) {
            // Tracee exited stop prematurely due to SIGKILL or equivalent.
            // Pretend the stop didn't happen.
            continue;
          }
          result.by_waitpid = true;
          LOGM(debug) << "  new status is " << current_->status();
          // Another task just became runnable, we're no longer in unlimited
          // ticks mode
          unlimited_ticks_mode = false;
          if (waited == current_) {
            break;
          }
          // If we got some other event, make sure the current thread has run
          // at least a little bit. We could change the ticks period here to
          // re-enable normal timeslice behavior, but we don't want to rely on
          // the kernel/hardware correctly changing the ticks period while the
          // counters are running. So instead, we just give it the remainder of
          // a 50ms time slice, after which the wait() call below will manually
          // PTRACE_INTERRUPT it.
          double elapsed = now - monotonic_now_sec();
          timeout = elapsed > 0.05 ? 0.0 : 0.05 - elapsed;
          LOGM(debug) << "  But that's not our current task...";
        } else {
          if (current_->wait(timeout)) {
            result.by_waitpid = true;
            LOGM(debug) << "  new status is " << current_->status();
          } else {
            // A SIGKILL or equivalent kicked the task out of the stop.
            // We are now running towards PTRACE_EVENT_EXIT or zombie status.
            // Even though we're PREVENT_SWITCH, we still have to switch.
            // The task won't be stopped so this is handled below.
          }
          break;
        }
      }
#ifdef MONITOR_UNSWITCHABLE_WAITS
      double wait_duration = monotonic_now_sec() - now;
      if (wait_duration >= 0.010) {
        LOGM(warn) << "Waiting for unswitchable " << current_->ev()
                   << " took " << 1000.0 * wait_duration << "ms";
      }
#endif
    }
    if (current_->is_stopped() || current_->was_reaped()) {
      validate_scheduled_task();
      return result;
    }
  }

  unlimited_ticks_mode = false;

  RecordTask* next = nullptr;
  // While a threadgroup is in execve, treat all tasks as blocked.
  while (!in_exec_tgid) {
    maybe_reset_high_priority_only_intervals(now);
    last_reschedule_in_high_priority_only_interval =
        in_high_priority_only_interval(now);
    WaitAggregator wait_aggregator((task_priority_set_total_count + task_round_robin_queue.size())/100 + 1);

    map<int, vector<RecordTask*>> attention_set_by_priority;
    for (pid_t tid : TraceeAttentionSet::read()) {
      if (current_ && current_->tid == tid) {
        // current_ will almost always be in the attention set because of
        // ptrace-stop activity related to when we last ran it.
        // It's fairer to leave it out of the attention set.
        continue;
      }
      RecordTask* t = session.find_task(tid);
      if (t) {
        attention_set_by_priority[t->priority].push_back(t);
      }
    }

    if (current_) {
      // Determine if we should run current_ again
      RecordTask* round_robin_task = get_round_robin_task();
      if (!round_robin_task) {
        next = find_next_runnable_task(wait_aggregator, attention_set_by_priority, &result.by_waitpid,
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
      if (!always_switch &&
          (!round_robin_task || round_robin_task == current_) &&
          (treat_as_high_priority(current_) ||
           !last_reschedule_in_high_priority_only_interval) &&
          current_->tick_count() < current_timeslice_end() &&
          is_task_runnable(current_, wait_aggregator, &result.by_waitpid)) {
        LOGM(debug) << "  Carrying on with task " << current_->tid;
        validate_scheduled_task();
        return result;
      }
      // Having rejected current_, be prepared to run the next task in the
      // round-robin queue.
      maybe_pop_round_robin_task(current_);
    }

    LOGM(debug) << "  need to reschedule";

    next = get_round_robin_task();
    if (next) {
      LOGM(debug) << "Trying task " << next->tid << " from yield queue";
      if (is_task_runnable(next, wait_aggregator, &result.by_waitpid)) {
        break;
      }
      maybe_pop_round_robin_task(next);
      continue;
    }

    next = find_next_runnable_task(wait_aggregator, attention_set_by_priority, &result.by_waitpid, INT32_MAX);
    if (!next && !wait_aggregator.exit_candidates().empty()) {
      // We need to check for tasks that have unexpectedly exited.
      // First check if there is any exit status pending. Normally there won't be.
      WaitOptions options;
      options.block_seconds = 0;
      options.consume = false;
      // We check for a stop_or_exit even though we'd really like to check for
      // just an exit. Unfortunately wait_exit does not work properly if we
      // don't consume the status and want to wait on any tracee.
      // If we have a stop, that's OK, we'll just do extra work here.
      WaitResult result = WaitManager::wait_stop_or_exit(options);
      if (result.code == WAIT_OK) {
        // Check which candidate has exited, if any.
        for (RecordTask* t : wait_aggregator.exit_candidates()) {
          if (WaitAggregator::try_wait_exit(t)) {
            next = t;
            break;
          }
        }
      }
    }

    if (next && !treat_as_high_priority(next) &&
        last_reschedule_in_high_priority_only_interval) {
      if (result.by_waitpid) {
        LOGM(debug)
            << "Waking up low-priority task with by_waitpid; not sleeping";
        // We must run this low-priority task. Fortunately it's just waking
        // up from a blocking syscall; we'll record the syscall event and then
        // (unless it was an interrupted syscall) we'll return to
        // get_next_thread, which will either run a higher priority thread
        // or (more likely) reach here again but in the !*by_waitpid case.
      } else {
        LOGM(debug)
            << "Waking up low-priority task without by_waitpid; sleeping";
        sleep_time(0.001);
        now = monotonic_now_sec();
        continue;
      }
    }
    break;
  }

  if (next) {
    LOGM(debug) << "  selecting task " << next->tid;
  } else {
    // All the tasks are blocked.
    // Wait for the next one to change state.

    // Clear the round-robin queue since we will no longer be able to service
    // those tasks in-order.
    while (RecordTask* t = get_round_robin_task()) {
      maybe_pop_round_robin_task(t);
    }

    LOGM(debug) << "  all tasks blocked, waiting for runnable ("
               << task_priority_set_total_count << " total)";

    WaitStatus status;
    do {
      double timeout = enable_poll ? 1 : 0;
      pid_t tid;
      WaitResultCode wait_result = wait_any(tid, status, timeout);
      if (wait_result == WAIT_NO_STATUS) {
        if (must_run_task) {
          FATAL() << "must_run_task but no status?";
        }
        result.interrupted_by_signal = true;
        return result;
      }
      if (wait_result == WAIT_NO_CHILD) {
        // It's possible that the original thread group was detached,
        // and the only thing left we were waiting for, in which case we
        // get ECHILD here. Just abort this record step, so the caller
        // can end the record session.
        return result;
      }
      LOGM(debug) << "  " << tid << " changed status to " << status;
      next = find_waited_task(session, tid, status);
      now = -1; // invalid, don't use
      if (next) {
        ASSERT(next,
               next->may_be_blocked() ||
                   status.ptrace_event() == PTRACE_EVENT_EXIT ||
                   status.reaped())
            << "Scheduled task should have been blocked";
        if (!next->did_waitpid(status)) {
          next = nullptr;
        } else if (in_exec_tgid && next->tgid() != in_exec_tgid) {
          // Some threadgroup is doing execve and this task isn't in
          // that threadgroup. Don't schedule this task until the execve
          // is complete.
          LOGM(debug) << "  ... but threadgroup " << in_exec_tgid << " is in execve, so ignoring for now";
          next = nullptr;
        }
      }
    } while (!next);
    result.by_waitpid = true;
    must_run_task = next;
  }

  if (current_ && current_ != next) {
    notify_descheduled(current_);
    if (is_logging_enabled(LOG_debug, __FILE__)) {
      LOGM(debug) << "Switching from " << current_->tid << "(" << current_->name()
                  << ") to " << next->tid << "(" << next->name() << ") (priority "
                  << current_->priority << " to " << next->priority << ") at "
                  << current_->trace_writer().time();
    }
  }

  maybe_reset_high_priority_only_intervals(now);
  current_ = next;
  if (!current_->in_round_robin_queue) {
    // Move it to the end of the per-priority task list
    remove_from_task_priority_set(current_);
    insert_into_task_priority_set(current_);
  }
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

bool Scheduler::CompareByScheduleOrder::operator()(
        RecordTask* a, RecordTask* b) const {
  return a->scheduler_token < b->scheduler_token;
}

void Scheduler::insert_into_task_priority_set(RecordTask* t) {
  t->scheduler_token = ++reschedule_count;
  task_priority_set[t->priority].tasks.insert(t);
  ++task_priority_set_total_count;
}

void Scheduler::remove_from_task_priority_set(RecordTask* t) {
  task_priority_set[t->priority].tasks.erase(t);
  --task_priority_set_total_count;
}

void Scheduler::on_create(RecordTask* t) {
  DEBUG_ASSERT(!t->in_round_robin_queue);
  if (enable_chaos) {
    // new tasks get a random priority
    t->priority = choose_random_priority(t);
  }
  insert_into_task_priority_set(t);
  unlimited_ticks_mode = false;
}

void Scheduler::on_destroy(RecordTask* t) {
  if (t == current_) {
    current_ = nullptr;
  }
  // When the last task in a threadgroup undergoing execve dies,
  // the execve is over.
  if (t->tgid() == in_exec_tgid &&
      t->thread_group()->task_set().size() == 1) {
    in_exec_tgid = 0;
  }

  if (t->in_round_robin_queue) {
    auto iter =
        find(task_round_robin_queue.begin(), task_round_robin_queue.end(), t);
    task_round_robin_queue.erase(iter);
  } else {
    remove_from_task_priority_set(t);
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
  remove_from_task_priority_set(t);
  t->priority = value;
  insert_into_task_priority_set(t);
}

static bool round_robin_scheduling_enabled() {
  static bool disabled = getenv("RR_DISABLE_ROUND_ROBIN") != nullptr;
  return !disabled;
}

void Scheduler::schedule_one_round_robin(RecordTask* t) {
  if (!round_robin_scheduling_enabled()) {
    LOGM(debug) << "Would schedule round-robin because of task " << t->tid << ", but disabled";
    return;
  }

  LOGM(debug) << "Scheduling round-robin because of task " << t->tid;

  ASSERT(t, t == current_);
  maybe_pop_round_robin_task(t);
  ASSERT(t, !t->in_round_robin_queue);

  for (auto p : task_priority_set) {
    for (RecordTask* tt : p.second.tasks) {
      if (tt != t && !tt->in_round_robin_queue) {
        task_round_robin_queue.push_back(tt);
        tt->in_round_robin_queue = true;
      }
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
  insert_into_task_priority_set(t);
}

void Scheduler::did_enter_execve(RecordTask* t) {
  ASSERT(t, !in_exec_tgid) <<
    "Entering execve while another execve is already happening in tgid " << in_exec_tgid;
  in_exec_tgid = t->tgid();
}

void Scheduler::did_exit_execve(RecordTask* t) {
  ASSERT(t, in_exec_tgid == t->tgid()) <<
    "Exiting an execve we didn't know about";
  in_exec_tgid = 0;
}

} // namespace rr
