/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static const char start_token = '!';
static const char sentinel_token = ' ';

static pthread_t reader;
static pthread_barrier_t barrier;
static pid_t reader_tid;
static int reader_caught_signal;

static int sockfds[2];

static void sighandler(__attribute__((unused)) int sig) {
  char c = sentinel_token;

  test_assert(sys_gettid() == reader_tid);
  ++reader_caught_signal;

  atomic_puts("r: in sighandler level 1 ...");

  test_assert(-1 == read(sockfds[1], &c, sizeof(c)) && EINTR == errno);
  atomic_printf("r: ... read level 1 '%c'\n", c);
  test_assert(c == sentinel_token);
}

static void sighandler2(__attribute__((unused)) int sig) {
  char c = sentinel_token;

  test_assert(sys_gettid() == reader_tid);
  ++reader_caught_signal;

  atomic_puts("r: in sighandler level 2 ...");

  test_assert(1 == read(sockfds[1], &c, sizeof(c)));
  atomic_printf("r: ... read level 2 '%c'\n", c);
  test_assert(c == start_token);
}

static void* reader_thread(__attribute__((unused)) void* dontcare) {
  struct sigaction act;
  struct timeval ts;
  int readsock = sockfds[1];
  char c = sentinel_token;
  int flags = 0;

  reader_tid = sys_gettid();

  act.sa_handler = sighandler;
  sigemptyset(&act.sa_mask);
  act.sa_flags = flags;
  sigaction(SIGUSR1, &act, NULL);

  act.sa_handler = sighandler2;
  sigemptyset(&act.sa_mask);
  act.sa_flags = flags;
  sigaction(SIGUSR2, &act, NULL);

  pthread_barrier_wait(&barrier);

  /* (Put another record in the syscallbuf.) */
  gettimeofday(&ts, NULL);

  atomic_puts("r: blocking on read, awaiting signal ...");

  test_assert(-1 == read(readsock, &c, sizeof(c)) && EINTR == errno);
  test_assert(2 == reader_caught_signal);
  atomic_printf("r: ... read level 0 '%c'\n", c);
  test_assert(c == sentinel_token);

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

  atomic_puts("M:   (longer nap)");

  usleep(500000);
  atomic_printf("M: finishing level 2 reader by writing '%c' to socket ...\n",
                token);
  write(sockfds[0], &token, sizeof(token));
  ++token;

  atomic_puts("M:   ... done");

  pthread_join(reader, NULL);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
