/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static char fifo_name[] = "fifo";

static volatile char ch;

static void do_stuff(void) {
  int i;
  for (i = 0; i < 10000; ++i) {
    ch = 7;
  }
}

/* This runs outside of rr to send async SIGKILL signals on demand */
static void do_killer(void) {
  int fd;
  char buf[4];
  uint32_t pid;
  fd = open(fifo_name, O_RDONLY);
  test_assert(fd >= 0);
  while (1) {
    struct timespec ts = { 0, 500000 };
    ssize_t s = read(fd, buf, 4);
    if (s == 0) {
      return;
    }
    test_assert(s == 4);
    memcpy(&pid, buf, 4);
    nanosleep(&ts, NULL);
    kill(pid, SIGKILL);
  }
}

int main(int argc, char** argv) {
  pid_t child;
  int i;
  int fd;
  mkfifo(fifo_name, 0600);

  if (argc > 1 && strcmp(argv[1], "killer") == 0) {
    do_killer();
    return 0;
  }

  fd = open(fifo_name, O_WRONLY);
  test_assert(fd >= 0);
  for (i = 0; i < 1000; ++i) {
    int ret;
    int status;
    char buf[4];
    ssize_t s;
    child = fork();
    if (!child) {
      while (1) {
        sched_yield();
        do_stuff();
      }
    }
    memcpy(buf, &child, 4);
    s = write(fd, buf, 4);
    test_assert(s == 4);
    ret = waitpid(child, &status, 0);
    test_assert(ret == child);
    test_assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
  }
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
