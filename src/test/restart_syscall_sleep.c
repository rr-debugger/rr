/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* When a signal without a handler interrupts a relative sleep, poll() or
   FUTEX_WAIT with a timeout, the kernel continues the syscall with
   restart_syscall, which waits until the original deadline. A traced task
   gets ignored signals too, so under rr the SIGALRMs that the second thread
   below sends whenever the main thread is asleep interrupt the sleeps many
   times. Each sleep ends once its deadline has passed.

   sigreturn makes a pending restart_syscall fail with EINTR. A signal
   handler that runs after the kernel has set up a restart_syscall returns
   to it, and the interrupted sleep fails with EINTR. The SIGUSR1 handler
   below sets up that restart in the signal frame.

   The kernel writes a sleep's remaining time when a signal interrupts a
   relative sleep, but not when the restart_syscall above fails with EINTR.
   rr may give the kernel scratch memory for the remaining time, and the
   handler fills that with other data first. */

#define SLEEP_MS 20

#if defined(__x86_64__)
#define RESULT_REG gregs[REG_RAX]
#define PC_REG gregs[REG_RIP]
#elif defined(__i386__)
#define RESULT_REG gregs[REG_EAX]
#define PC_REG gregs[REG_EIP]
#elif defined(__aarch64__)
#define RESULT_REG regs[0]
#define PC_REG pc
#else
#error Unknown architecture
#endif

static int scratch_pipe[2];

/* rr gives a read() that it doesn't buffer scratch memory for the data.
   16 bytes cover the remaining-time argument of each sleep syscall. */
static void fill_scratch(void) {
  char buf[16];
  memset(buf, 0x7f, sizeof(buf));
  test_assert(sizeof(buf) == write(scratch_pipe[1], buf, sizeof(buf)));
  test_assert(sizeof(buf) == unbufferable_syscall(SYS_read, scratch_pipe[0],
                                                  (uintptr_t)buf,
                                                  sizeof(buf)));
}

static struct timespec handler_sleep_request;
/* The sleep syscall's first argument. On aarch64 the kernel puts it back in
   x0 for a restart. */
static uintptr_t handler_sleep_arg1;
static int in_handler_sleep;
static int restart_set_up;

static void handle_usr1(__attribute__((unused)) int sig,
                        __attribute__((unused)) siginfo_t* si, void* p) {
  ucontext_t* ctx = (ucontext_t*)p;
  if (!__atomic_load_n(&in_handler_sleep, __ATOMIC_SEQ_CST) ||
      (long)ctx->uc_mcontext.RESULT_REG != -EINTR) {
    /* The signal didn't interrupt the sleep. */
    return;
  }
  fill_scratch();
  /* Return to the syscall instruction with the registers the kernel sets
     up for restart_syscall. */
#if defined(__aarch64__)
  ctx->uc_mcontext.pc -= 4;
  ctx->uc_mcontext.regs[0] =
      __atomic_load_n(&handler_sleep_arg1, __ATOMIC_SEQ_CST);
  ctx->uc_mcontext.regs[8] = SYS_restart_syscall;
#else
  ctx->uc_mcontext.PC_REG -= 2;
  ctx->uc_mcontext.RESULT_REG = SYS_restart_syscall;
#endif
  __atomic_store_n(&restart_set_up, 1, __ATOMIC_SEQ_CST);
}

/* Sends SIGUSR1 once, |delay_ms| ms from now. sleep_with_handler() arms it
   before a sleep of 1 s, and if it arrives before the sleep starts, tries
   again with twice the delay, up to 640 ms. */
static void arm_timer(timer_t timer, int delay_ms) {
  struct itimerspec timer_value;
  memset(&timer_value, 0, sizeof(timer_value));
  timer_value.it_value.tv_nsec = delay_ms * 1000000L;
  test_assert(0 == timer_settime(timer, 0, &timer_value, NULL));
}

static void sleep_with_handler(timer_t timer, int use_clock_nanosleep) {
  struct timespec remaining;
  int delay_ms = 5;
  int ret;

  __atomic_store_n(&handler_sleep_arg1,
                   use_clock_nanosleep ? (uintptr_t)CLOCK_MONOTONIC
                                       : (uintptr_t)&handler_sleep_request,
                   __ATOMIC_SEQ_CST);
  do {
    handler_sleep_request.tv_sec = 1;
    handler_sleep_request.tv_nsec = 0;
    memset(&remaining, 0, sizeof(remaining));
    __atomic_store_n(&restart_set_up, 0, __ATOMIC_SEQ_CST);
    arm_timer(timer, delay_ms);
    __atomic_store_n(&in_handler_sleep, 1, __ATOMIC_SEQ_CST);
    if (use_clock_nanosleep) {
      ret = clock_nanosleep(CLOCK_MONOTONIC, 0, &handler_sleep_request,
                            &remaining);
    } else {
      ret = syscall(SYS_nanosleep, &handler_sleep_request, &remaining)
                ? errno
                : 0;
    }
    __atomic_store_n(&in_handler_sleep, 0, __ATOMIC_SEQ_CST);
    if (delay_ms < 640) {
      delay_ms *= 2;
    }
    /* If SIGUSR1 arrived outside the sleep, try again. */
  } while (!__atomic_load_n(&restart_set_up, __ATOMIC_SEQ_CST));

  atomic_printf("%s: %s\n",
                use_clock_nanosleep ? "clock_nanosleep" : "nanosleep",
                strerror(ret));
  test_assert(ret == EINTR);
  /* The kernel wrote the remaining time when SIGUSR1 interrupted the sleep.
     It includes the timer slack, so it can be a little more than the
     request. */
  test_assert(remaining.tv_sec > 0 || remaining.tv_nsec > 0);
  test_assert(remaining.tv_sec >= 0 &&
              remaining.tv_sec <= handler_sleep_request.tv_sec);
  test_assert(remaining.tv_nsec >= 0 && remaining.tv_nsec < 1000000000);
}

static pid_t sleeper_tid;
/* Nonzero while the main thread sleeps. */
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

static void sleep_with_ignored_signals(void) {
  struct timespec request = { 0, SLEEP_MS * 1000000 };
  struct pollfd pfd;
  pthread_t sender;
  int fds[2];
  int futex_word = 0;
  int ret;

  test_assert(SIG_ERR != signal(SIGALRM, SIG_IGN));
  test_assert(0 == pipe(fds));
  sleeper_tid = sys_gettid();
  test_assert(0 == pthread_create(&sender, NULL, send_ignored_signals, NULL));
  while (!__atomic_load_n(&sender_running, __ATOMIC_SEQ_CST)) {
    sched_yield();
  }

  __atomic_store_n(&sleeping, 1, __ATOMIC_SEQ_CST);
  ret = syscall(SYS_nanosleep, &request, NULL);
  __atomic_store_n(&sleeping, 0, __ATOMIC_SEQ_CST);
  test_assert(ret == 0);

  __atomic_store_n(&sleeping, 1, __ATOMIC_SEQ_CST);
  ret = clock_nanosleep(CLOCK_MONOTONIC, 0, &request, NULL);
  __atomic_store_n(&sleeping, 0, __ATOMIC_SEQ_CST);
  test_assert(ret == 0);

  pfd.fd = fds[0];
  pfd.events = POLLIN;
  pfd.revents = -1;
  __atomic_store_n(&sleeping, 1, __ATOMIC_SEQ_CST);
  ret = poll(&pfd, 1, SLEEP_MS);
  __atomic_store_n(&sleeping, 0, __ATOMIC_SEQ_CST);
  test_assert(ret == 0);
  test_assert(pfd.revents == 0);

  __atomic_store_n(&sleeping, 1, __ATOMIC_SEQ_CST);
  ret = syscall(SYS_futex, &futex_word, FUTEX_WAIT_PRIVATE, 0, &request,
                NULL, 0);
  __atomic_store_n(&sleeping, 0, __ATOMIC_SEQ_CST);
  test_assert(ret == -1 && errno == ETIMEDOUT);

  __atomic_store_n(&done_sleeping, 1, __ATOMIC_SEQ_CST);
  test_assert(0 == pthread_join(sender, NULL));
}

int main(void) {
  struct sigaction sa;
  struct sigevent sev;
  timer_t timer;

  test_assert(0 == pipe(scratch_pipe));

  memset(&sa, 0, sizeof(sa));
  sa.sa_sigaction = handle_usr1;
  sa.sa_flags = SA_SIGINFO;
  test_assert(0 == sigaction(SIGUSR1, &sa, NULL));
  memset(&sev, 0, sizeof(sev));
  sev.sigev_notify = SIGEV_SIGNAL;
  sev.sigev_signo = SIGUSR1;
  test_assert(0 == timer_create(CLOCK_MONOTONIC, &sev, &timer));

  sleep_with_handler(timer, 0);
  sleep_with_handler(timer, 1);
  test_assert(0 == timer_delete(timer));

  sleep_with_ignored_signals();

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
