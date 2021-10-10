/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static volatile int caught_sig = 0;

pthread_barrier_t bar;
char value[8];
int fd;

void catcher(__attribute__((unused)) int signum,
             __attribute__((unused)) siginfo_t* siginfo_ptr,
             __attribute__((unused)) void* ucontext_ptr) {
  caught_sig = signum;
  test_assert(sys_gettid() == getpid());
}

void* receiver(__attribute__((unused)) void* name) {
  sigset_t sigs;

  sigemptyset(&sigs);
  sigaddset(&sigs, SIGALRM);
  test_assert(0 == pthread_sigmask(SIG_BLOCK, &sigs, NULL));
  test_assert(value[0] == 0);
  // Synchronize with the main thread to allow it to proceed.
  pthread_barrier_wait(&bar);
  // Immediately block again.
  pthread_barrier_wait(&bar);

  // Give the main thread a chance to exit.
  // No non-racy way to do this afaict.
  sleep(1);

  test_assert(0 < read(fd, &value[0], 8));
  close(fd);

  // Assert that we wrote into value.
  test_assert(value[0] == 0x7f);

  atomic_puts("EXIT-SUCCESS");
  exit(0);
  return NULL;
}

int main(void) {
  struct sigaction sact;
  int counter;
  pthread_t thread;

  sigemptyset(&sact.sa_mask);
  sact.sa_flags = SA_SIGINFO;
  sact.sa_sigaction = catcher;
  sigaction(SIGALRM, &sact, NULL);

  pthread_barrier_init(&bar, NULL, 2);
  pthread_create(&thread, NULL, receiver, NULL);
  /* Synchronize with the child thread so we're sure it won't take the signal */
  pthread_barrier_wait(&bar);

  fd = open("/proc/self/exe", O_RDONLY);
  test_assert(fd >= 0);

  alarm(1); /* timer will pop in 1 second */

  size_t page_size = sysconf(_SC_PAGESIZE);
  void* p =
      mmap(NULL, page_size, PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  test_assert(p != MAP_FAILED);

  test_assert(0 == mprotect(p, page_size, PROT_NONE));

  for (counter = 0; counter >= 0 && !caught_sig; counter++) {
    if (counter % 10000000 == 0) {
      write(STDOUT_FILENO, ".", 1);
    }
  }

  /* Allow the child thread to proceed */
  pthread_barrier_wait(&bar);
  syscall(SYS_exit, 0);

  return 0;
}
