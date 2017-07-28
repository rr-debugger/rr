/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static const char start_token = '!';
static const char sentinel_token = ' ';

static pthread_t reader;
static pthread_barrier_t barrier;
static pid_t reader_tid;
static int reader_caught_signal;

static int sockfds[2];

pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cond = PTHREAD_COND_INITIALIZER;

static void cond_wait(int secs) {
  struct timespec ts;

  clock_gettime(CLOCK_REALTIME, &ts);
  ts.tv_sec += secs;

  test_assert(ETIMEDOUT == pthread_cond_timedwait(&cond, &lock, &ts));
}

static void sighandler(__attribute__((unused)) int sig) {
  test_assert(sys_gettid() == reader_tid);
  ++reader_caught_signal;

  atomic_puts("r: in sighandler level 1 ...");
  cond_wait(1);
  atomic_puts("r: ... wait done");
}

static void* reader_thread(__attribute__((unused)) void* dontcare) {
  char token = start_token;
  struct sigaction act;
  int readsock = sockfds[1];
  char c = sentinel_token;
  int flags = 0;

  pthread_mutex_lock(&lock);

  reader_tid = sys_gettid();

  flags = SA_RESTART;

  act.sa_handler = sighandler;
  sigemptyset(&act.sa_mask);
  act.sa_flags = flags;
  sigaction(SIGUSR1, &act, NULL);

  act.sa_handler = SIG_IGN;
  sigemptyset(&act.sa_mask);
  act.sa_flags = flags;
  sigaction(SIGUSR2, &act, NULL);

  pthread_barrier_wait(&barrier);

  atomic_puts("r: blocking on read, awaiting signal ...");

  test_assert(1 == read(readsock, &c, sizeof(c)));
  test_assert(1 == reader_caught_signal);

  atomic_printf("r: ... read level 0 '%c'\n", c);
  test_assert(c == token);

  return NULL;
}

int main(void) {
  char token = start_token;
  struct timeval ts;

  /* (Kick on the syscallbuf if it's enabled.) */
  gettimeofday(&ts, NULL);

  socketpair(AF_LOCAL, SOCK_STREAM, 0, sockfds);

  pthread_barrier_init(&barrier, NULL, 2);
  pthread_create(&reader, NULL, reader_thread, NULL);

  pthread_barrier_wait(&barrier);

  /* Force a blocked read() that's interrupted by a SIGUSR1,
   * which then itself blocks on read() and succeeds. */
  atomic_puts("M: sleeping ...");
  usleep(500000);

  atomic_puts("M: killing reader ...");
  pthread_kill(reader, SIGUSR1);
  atomic_puts("M:   (quick nap)");
  usleep(100000);

  atomic_puts("M: killing reader again ...");
  pthread_kill(reader, SIGUSR2);

  usleep(500000);
  atomic_printf("M: finishing level 0 reader by writing '%c' to socket ...\n",
                token);
  write(sockfds[0], &token, sizeof(token));
  ++token;

  atomic_puts("M:   ... done");

  pthread_join(reader, NULL);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
