/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void* do_thread(__attribute__((unused)) void* p) {
  atomic_puts("EXIT-SUCCESS");
  return NULL;
}

int main(void) {
  pthread_t thread;
  struct rlimit limit;
  int ret = getrlimit(RLIMIT_NOFILE, &limit);
  int new_fd;
  rlim_t initial_limit = limit.rlim_cur;
  test_assert(ret >= 0);

  if (initial_limit + 10 > limit.rlim_max) {
    atomic_puts("Current soft limit cannot be increased enough, skipping test");
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }

  /* Increase soft limit. */
  limit.rlim_cur += 10;
  ret = setrlimit(RLIMIT_NOFILE, &limit);
  test_assert(ret >= 0);

  /* Consume file descriptors until we've allocated all previously available descriptors (plus one). */
  do {
    new_fd = open("/dev/null", O_RDONLY);
    test_assert(new_fd >= 0);
  } while (new_fd < (int)initial_limit);

  /* This will allocate new fds for thread stack and syscallbuf stuff */
  pthread_create(&thread, NULL, do_thread, NULL);
  pthread_join(thread, NULL);

  return 0;
}
