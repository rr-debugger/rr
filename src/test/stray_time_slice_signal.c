/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  int i;
  int fd = open("/dev/zero", O_RDONLY);
  int sum = 0;
  pid_t pid;
  int status;

  test_assert(fd >= 0);

  pid = fork();
  if (!pid) {
    pid_t pp = getppid();
    for (i = 0; i < 1000; ++i) {
      kill(pp, SIGCHLD);
    }
    return 77;
  }

  for (i = 0; i < 1000; ++i) {
    int j;
    for (j = 0; j < i % 50; ++j) {
      sum += j * i;
    }
  }

  test_assert(pid == wait(&status));

  atomic_printf("token = %d\n", sum);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
