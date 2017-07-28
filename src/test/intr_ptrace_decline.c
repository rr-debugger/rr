/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static const char start_token = '!';
static const char sentinel_token = ' ';

static pthread_t reader;
static pthread_barrier_t barrier;

static int sockfds[2];

pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cond = PTHREAD_COND_INITIALIZER;

static void fin_intr_sleep(int secs) {
  struct timespec req = {.tv_sec = secs };
  struct timespec rem = {.tv_sec = -1, .tv_nsec = -1 };

  test_assert(0 == nanosleep(&req, &rem));
  /* We would normally assert that the outparam wasn't touched
   * for this successful sleep, but ptrace-declined signals are
   * an odd case, the only way a nanosleep can restart.  The
   * kernel has been observed to write back the outparam at
   * interrupt time, so we track that semantics here.
   *
   *  test_assert(-1 == rem.tv_sec && -1 == rem.tv_nsec);
   */
}

static void fin_poll(int secs) {
  static int pipefds[2];
  struct pollfd pfd;
  int ret;

  pipe(pipefds);

  pfd.fd = pipefds[0];
  pfd.events = POLLIN;
  pfd.revents = -1;
  errno = 0;

  ret = poll(&pfd, 1, 1000 * secs);
  atomic_printf("r: poll() returns %d; pfd.revents = 0x%x\n", ret, pfd.revents);
  test_assert(0 == ret);
  test_assert(0 == pfd.revents);
}

static void cond_wait(int secs) {
  struct timespec ts;

  clock_gettime(CLOCK_REALTIME, &ts);
  ts.tv_sec += secs;

  test_assert(ETIMEDOUT == pthread_cond_timedwait(&cond, &lock, &ts));
}

static void* reader_thread(__attribute__((unused)) void* dontcare) {
  char token = start_token;
  int readsock = sockfds[1];
  char c = sentinel_token;

  pthread_mutex_lock(&lock);

  pthread_barrier_wait(&barrier);

  atomic_puts("r: blocking on sleep, awaiting signal ...");
  fin_intr_sleep(1);

  atomic_puts("r: blocking on poll, awaiting signal ...");
  fin_poll(1);

  atomic_puts("r: blocking on futex, awaiting signal ...");
  cond_wait(1);

  atomic_puts("r: blocking on read, awaiting signal ...");
  test_assert(1 == read(readsock, &c, sizeof(c)));
  atomic_printf("r: ... read '%c'\n", c);
  test_assert(c == token);

  return NULL;
}

int main(void) {
  char token = start_token;
  struct timeval ts;
  int i;

  /* (Kick on the syscallbuf if it's enabled.) */
  gettimeofday(&ts, NULL);

  socketpair(AF_LOCAL, SOCK_STREAM, 0, sockfds);

  pthread_barrier_init(&barrier, NULL, 2);
  pthread_create(&reader, NULL, reader_thread, NULL);

  pthread_barrier_wait(&barrier);

  atomic_puts("M: sleeping ...");
  usleep(500000);
  for (i = 0; i < 4; ++i) {
    atomic_puts("M: killing reader ...");
    pthread_kill(reader, SIGUSR1);
    atomic_puts("M: sleeping ...");
    sleep(1);
  }
  atomic_printf("M: finishing original reader by writing '%c' to socket ...\n",
                token);
  write(sockfds[0], &token, sizeof(token));
  ++token;

  atomic_puts("M:   ... done");

  pthread_join(reader, NULL);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
