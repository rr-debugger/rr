/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static const char start_token = '!';
static const char sentinel_token = ' ';

static pthread_t reader;
static pthread_barrier_t barrier;

static int sockfds[2];

static void* reader_thread(__attribute__((unused)) void* dontcare) {
  int readsock = sockfds[1];
  char c = sentinel_token;
  struct timeval tv;

  pthread_barrier_wait(&barrier);

  atomic_puts("r: blocking on read ...");

  test_assert(1 == read(readsock, &c, sizeof(c)));

  gettimeofday(&tv, NULL);

  atomic_printf("r: ... read '%c'\n", c);
  test_assert(c == start_token);

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
  atomic_printf("M: finishing reader by writing '%c' to socket ...\n", token);
  write(sockfds[0], &token, sizeof(token));
  ++token;

  atomic_puts("M:   ... done");

  pthread_join(reader, NULL);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
