/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#if defined(__i386__)
/* Don't do anything for 32 bit. */
#elif defined(__x86_64__)
static int pipe_fds[2];

/* Syscall-bufferable version of read(fd, buf, 1).
   Designed to be patched at the mov $0xffffffffffffffff,%%r9.
   This will be patched only after the syscall returns. */
static void read_one_byte(int fd) {
  char buf[1];
  __asm__ __volatile__("mov $0xffffffffffffffff,%%r9\n\t"
                       "syscall\n\t"
                       "or %%rsp,%%rsp\n\t"
                       : : "a"(SYS_read), "D"(fd), "S"(buf), "d"(1)
                       : "r9");
}

static void handle_signal(__attribute__((unused)) int sig) {}

static void* do_thread(__attribute__((unused)) void* p) {
  /* Try to read a byte from pipe_fds[0]; this should block forever. */
  read_one_byte(pipe_fds[0]);
  /* We should never reach here because the read should automatically restart
     after the signal */
  atomic_puts("FAILED");
  exit(1);
  return NULL;
}
#else
#error unsupported arch
#endif

int main(void) {
#ifdef __x86_64__
  pthread_t thread;
  struct timespec ten_ms = { 0, 10000000 };

  pipe(pipe_fds);
  signal(SIGUSR1, handle_signal);

  pthread_create(&thread, NULL, do_thread, NULL);
  /* Allow the child thread to run until it blocks in the buffered read. */
  nanosleep(&ten_ms, NULL);
  /* Read from an invalid fd. This should trigger syscallbuf patching
     of the syscall in read_one_byte. That patching needds to *fail*
     because the child thread is currently blocked in the syscall
     and will need to restart the syscall after we signal it;
     if the syscall instruction is patched out, that restart
     won't happen and this test fails. */
  read_one_byte(-1);
  pthread_kill(thread, SIGUSR1);
  // The child thread should still be blocked. Let it run again to make sure.
  nanosleep(&ten_ms, NULL);
#endif
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
