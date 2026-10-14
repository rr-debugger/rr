/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util_internal.h"

/* The main thread does blocking read()s through the syscall buffer, each
   after asking rr for a time-slice signal a different number of ticks later,
   so that for some of them the signal arrives in the syscall buffer code.
   rr defers the signal, the read() blocks, and rr interrupts it to handle the
   signal. With -s, rr then records a SCHED while the main thread is still
   stopped at the exit of the interrupted read(), and switches to the other
   thread, which never blocks. The other thread writes a byte for each read()
   once the main thread is in it. */

#define NUM_READS 128
/* rr can't program a time-slice period below 32 ticks on some CPUs, so spin
   for longer than that before each read(). */
#define SPIN_TICKS 40

static int fds[2];
static pid_t main_tid;
static volatile int reads_done;

static int main_thread_in_read(void) {
  char path[PATH_MAX];
  char buf[1024];
  long nr;
  unsigned long arg1;
  int fd;
  ssize_t len;

  sprintf(path, "/proc/self/task/%d/syscall", main_tid);
  fd = open(path, O_RDONLY);
  test_assert(fd >= 0);
  len = read(fd, buf, sizeof(buf) - 1);
  test_assert(len > 0);
  buf[len] = 0;
  test_assert(0 == close(fd));
  return sscanf(buf, "%ld 0x%lx", &nr, &arg1) == 2 && nr == SYS_read &&
         arg1 == (unsigned long)fds[0];
}

static void* do_thread(__attribute__((unused)) void* p) {
  int written = 0;
  while (written < NUM_READS) {
    if (reads_done == written && main_thread_in_read()) {
      test_assert(1 == write(fds[1], "x", 1));
      ++written;
    }
  }
  return NULL;
}

static void spin(int n) {
  volatile int i;
  for (i = 0; i < n; ++i) {
  }
}

int main(void) {
  pthread_t thread;
  char ch;
  int i;

  if (!running_under_rr()) {
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }

  test_assert(0 == pipe(fds));
  main_tid = sys_gettid();
  test_assert(0 == pthread_create(&thread, NULL, do_thread, NULL));

  for (i = 0; i < NUM_READS; ++i) {
    test_assert(0 == syscall(SYS_rrcall_arm_time_slice,
                             SPIN_TICKS + i, (long)0, (long)0, (long)0,
                             (long)0, (long)0));
    spin(SPIN_TICKS);
    test_assert(1 == read(fds[0], &ch, 1));
    reads_done = i + 1;
  }

  test_assert(0 == pthread_join(thread, NULL));
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
