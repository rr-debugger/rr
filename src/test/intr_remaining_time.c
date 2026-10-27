/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* When a signal interrupts select(), pselect6 or ppoll, the kernel writes
   the remaining time to the timeout argument, and a restart of the syscall
   waits only for that time. A traced task gets ignored signals too, so under
   rr the SIGALRMs that the second thread below sends whenever the main
   thread is asleep interrupt the waits many times. Each wait ends once its
   timeout has passed.

   The kernel doesn't write the remaining-time argument of a sleep with
   TIMER_ABSTIME. rr may give the kernel scratch memory for a syscall's
   buffers, and fill_scratch() fills that with other data before each such
   sleep. */

#define SLEEP_MS 20

#define REMAINING_SEC 1234
#define REMAINING_NSEC 5678

/* The kernel's struct for clock_nanosleep_time64. */
struct kernel_timespec64 {
  int64_t tv_sec;
  int64_t tv_nsec;
};

/* The kernel's struct for pselect6 and ppoll. */
struct kernel_timespec {
  long tv_sec;
  long tv_nsec;
};

static int scratch_pipe[2];

/* rr gives a read() that it doesn't buffer scratch memory for the data. */
static void fill_scratch(void) {
  char buf[sizeof(struct kernel_timespec64)];
  memset(buf, 0x7f, sizeof(buf));
  test_assert(sizeof(buf) == write(scratch_pipe[1], buf, sizeof(buf)));
  test_assert(sizeof(buf) == unbufferable_syscall(SYS_read, scratch_pipe[0],
                                                  (uintptr_t)buf,
                                                  sizeof(buf)));
}

static void handle_usr1(__attribute__((unused)) int sig) {}

/* Sends SIGUSR1 once, |delay_ms| ms from now. The parts below arm it
   before a wait of 1 s, and if it arrives before the wait starts, they try
   again with the delay that next_delay() returns. */
static void arm_timer(timer_t timer, int delay_ms) {
  struct itimerspec timer_value;
  memset(&timer_value, 0, sizeof(timer_value));
  timer_value.it_value.tv_nsec = delay_ms * 1000000L;
  test_assert(0 == timer_settime(timer, 0, &timer_value, NULL));
}

static int next_delay(int delay_ms) {
  return delay_ms < 640 ? delay_ms * 2 : delay_ms;
}

static void disarm_timer(timer_t timer) {
  struct itimerspec timer_value;
  memset(&timer_value, 0, sizeof(timer_value));
  test_assert(0 == timer_settime(timer, 0, &timer_value, NULL));
}

static void check_remaining(const char* name, int64_t sec, int64_t nsec) {
  if (sec != REMAINING_SEC || nsec != REMAINING_NSEC) {
    atomic_printf("%s changed the remaining time to %llx.%llx\n", name,
                  (unsigned long long)sec, (unsigned long long)nsec);
  }
  test_assert(sec == REMAINING_SEC && nsec == REMAINING_NSEC);
}

/* Make clock_nanosleep (clock_nanosleep_time64 if |use_time64|) with
   TIMER_ABSTIME and a deadline |sec| seconds from now. Returns the syscall's
   result, and -ENOSYS if the syscall doesn't exist. */
static int absolute_sleep(int use_time64, int sec) {
  struct timespec now;
  int ret;

  test_assert(0 == clock_gettime(CLOCK_MONOTONIC, &now));
  fill_scratch();
  if (use_time64) {
    struct kernel_timespec64 deadline = { now.tv_sec + sec, now.tv_nsec };
    struct kernel_timespec64 remaining = { REMAINING_SEC, REMAINING_NSEC };
    if (RR_clock_nanosleep_time64 < 0) {
      return -ENOSYS;
    }
    ret = syscall(RR_clock_nanosleep_time64, CLOCK_MONOTONIC, TIMER_ABSTIME,
                  &deadline, &remaining);
    check_remaining("clock_nanosleep_time64", remaining.tv_sec,
                    remaining.tv_nsec);
  } else {
    struct timespec deadline = { now.tv_sec + sec, now.tv_nsec };
    struct timespec remaining = { REMAINING_SEC, REMAINING_NSEC };
    ret = syscall(SYS_clock_nanosleep, CLOCK_MONOTONIC, TIMER_ABSTIME,
                  &deadline, &remaining);
    check_remaining("clock_nanosleep", remaining.tv_sec, remaining.tv_nsec);
  }
  return ret ? -errno : 0;
}

/* SIGUSR1 interrupts an absolute sleep of 1 s. */
static void absolute_sleep_with_handler(timer_t timer, int use_time64) {
  int delay_ms = 5;
  int ret;
  do {
    arm_timer(timer, delay_ms);
    ret = absolute_sleep(use_time64, 1);
    delay_ms = next_delay(delay_ms);
  } while (ret == 0);
  if (ret == -ENOSYS) {
    disarm_timer(timer);
  }
  test_assert(ret == -EINTR || ret == -ENOSYS);
}

/* Waits in select() (|which| 0), pselect6 (1) or ppoll (2) with a timeout
   of 1 s until SIGUSR1 interrupts the wait, and checks the remaining time
   in the timeout argument. */
static void timeout_with_handler(timer_t timer, int which) {
  static const char* const names[] = { "select", "pselect6", "ppoll" };
  int fd = scratch_pipe[0];
  long long remaining_us;
  int delay_ms = 5;
  int ret;

  do {
    struct timeval tv = { 1, 0 };
    struct kernel_timespec ts = { 1, 0 };
    struct pollfd pfd;
    fd_set read_fds;

    FD_ZERO(&read_fds);
    FD_SET(fd, &read_fds);
    pfd.fd = fd;
    pfd.events = POLLIN;
    fill_scratch();
    arm_timer(timer, delay_ms);
    delay_ms = next_delay(delay_ms);
    if (which == 0) {
      ret = select(fd + 1, &read_fds, NULL, NULL, &tv);
      remaining_us = tv.tv_sec * 1000000LL + tv.tv_usec;
    } else if (which == 1) {
      ret = syscall(SYS_pselect6, fd + 1, &read_fds, NULL, NULL, &ts, NULL);
      remaining_us = ts.tv_sec * 1000000LL + ts.tv_nsec / 1000;
    } else {
      ret = syscall(SYS_ppoll, &pfd, 1, &ts, NULL, 8);
      remaining_us = ts.tv_sec * 1000000LL + ts.tv_nsec / 1000;
    }
  } while (ret == 0);

  atomic_printf("%s: %s\n", names[which], strerror(errno));
  test_assert(ret == -1 && errno == EINTR);
  if (remaining_us < 0 || remaining_us >= 1000000) {
    atomic_printf("%s left %lld us of its 1 s timeout\n", names[which],
                  remaining_us);
    test_assert(0);
  }
}

static pid_t sleeper_tid;
/* Nonzero while the main thread waits. */
static int sleeping;
static int sender_running;
static int done_sleeping;

static void* send_ignored_signals(__attribute__((unused)) void* arg) {
  struct timespec pause = { 0, 1000000 };
  test_assert(sleeper_tid > 1);
  __atomic_store_n(&sender_running, 1, __ATOMIC_SEQ_CST);
  while (!__atomic_load_n(&done_sleeping, __ATOMIC_SEQ_CST)) {
    if (__atomic_load_n(&sleeping, __ATOMIC_SEQ_CST) &&
        get_task_state(sleeper_tid) == 'S' &&
        __atomic_load_n(&sleeping, __ATOMIC_SEQ_CST)) {
      test_assert(0 == syscall(SYS_tgkill, getpid(), sleeper_tid, SIGALRM));
    }
    test_assert(0 == nanosleep(&pause, NULL));
  }
  return NULL;
}

static void wait_with_ignored_signals(void) {
  struct timespec request = { 0, SLEEP_MS * 1000000 };
  struct timeval timeout = { 0, SLEEP_MS * 1000 };
  struct pollfd pfd;
  fd_set read_fds;
  pthread_t sender;
  int fds[2];
  int ret;

  test_assert(SIG_ERR != signal(SIGALRM, SIG_IGN));
  test_assert(0 == pipe(fds));
  sleeper_tid = sys_gettid();
  test_assert(0 == pthread_create(&sender, NULL, send_ignored_signals, NULL));
  while (!__atomic_load_n(&sender_running, __ATOMIC_SEQ_CST)) {
    sched_yield();
  }

  FD_ZERO(&read_fds);
  FD_SET(fds[0], &read_fds);
  __atomic_store_n(&sleeping, 1, __ATOMIC_SEQ_CST);
  ret = select(fds[0] + 1, &read_fds, NULL, NULL, &timeout);
  __atomic_store_n(&sleeping, 0, __ATOMIC_SEQ_CST);
  test_assert(ret == 0);

  FD_ZERO(&read_fds);
  FD_SET(fds[0], &read_fds);
  __atomic_store_n(&sleeping, 1, __ATOMIC_SEQ_CST);
  ret = pselect(fds[0] + 1, &read_fds, NULL, NULL, &request, NULL);
  __atomic_store_n(&sleeping, 0, __ATOMIC_SEQ_CST);
  test_assert(ret == 0);

  pfd.fd = fds[0];
  pfd.events = POLLIN;
  pfd.revents = -1;
  __atomic_store_n(&sleeping, 1, __ATOMIC_SEQ_CST);
  ret = ppoll(&pfd, 1, &request, NULL);
  __atomic_store_n(&sleeping, 0, __ATOMIC_SEQ_CST);
  test_assert(ret == 0);
  test_assert(pfd.revents == 0);

  __atomic_store_n(&done_sleeping, 1, __ATOMIC_SEQ_CST);
  test_assert(0 == pthread_join(sender, NULL));
}

int main(void) {
  struct sigaction sa;
  struct sigevent sev;
  timer_t timer;
  int ret;

  test_assert(0 == pipe(scratch_pipe));
  test_assert(absolute_sleep(0, 0) == 0);
  ret = absolute_sleep(1, 0);
  test_assert(ret == 0 || ret == -ENOSYS);

  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = handle_usr1;
  test_assert(0 == sigaction(SIGUSR1, &sa, NULL));
  memset(&sev, 0, sizeof(sev));
  sev.sigev_notify = SIGEV_SIGNAL;
  sev.sigev_signo = SIGUSR1;
  test_assert(0 == timer_create(CLOCK_MONOTONIC, &sev, &timer));

  absolute_sleep_with_handler(timer, 0);
  absolute_sleep_with_handler(timer, 1);
  timeout_with_handler(timer, 0);
  timeout_with_handler(timer, 1);
  timeout_with_handler(timer, 2);
  test_assert(0 == timer_delete(timer));

  wait_with_ignored_signals();

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
