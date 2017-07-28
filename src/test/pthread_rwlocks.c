/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static pthread_rwlock_t lock = PTHREAD_RWLOCK_INITIALIZER;

static int pipe_fds[2];

static void* start_thread(__attribute__((unused)) void* p) {
  pthread_rwlock_rdlock(&lock);
  pthread_rwlock_unlock(&lock);

  test_assert(1 == write(pipe_fds[1], "x", 1));

  pthread_rwlock_wrlock(&lock);
  pthread_rwlock_unlock(&lock);

  return NULL;
}

int main(void) {
  pthread_t thread;
  char ch;

  test_assert(0 == pipe(pipe_fds));

  pthread_rwlock_rdlock(&lock);

  pthread_create(&thread, NULL, start_thread, NULL);

  test_assert(1 == read(pipe_fds[0], &ch, 1));

  pthread_rwlock_unlock(&lock);

  pthread_join(thread, NULL);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
