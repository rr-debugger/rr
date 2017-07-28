/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#define NUM_THREADS 100

static int pipe_fds[2];

static void read_all(int fd, char* buf, size_t size) {
  while (size > 0) {
    ssize_t ret = read(fd, buf, size);
    test_assert(ret > 0);
    size -= ret;
    buf += ret;
  }
}

static void* thread(__attribute__((unused)) void* p) {
  int fd = open("/dev/zero", O_RDONLY);
  char buf[1000000];
  test_assert(fd >= 0);
  read_all(fd, buf, sizeof(buf));
  read(pipe_fds[0], buf, 1);
  test_assert(0);
  return NULL;
}

int main(void) {
  pthread_t threads[NUM_THREADS];
  int i;

  test_assert(0 == pipe(pipe_fds));

  for (i = 0; i < NUM_THREADS; ++i) {
    test_assert(0 == pthread_create(&threads[i], NULL, thread, NULL));
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
