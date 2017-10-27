/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static volatile int caught_sig = 0;

void catcher(__attribute__((unused)) int signum,
             __attribute__((unused)) siginfo_t* siginfo_ptr,
             __attribute__((unused)) void* ucontext_ptr) {
  caught_sig = signum;
}

int main(void) {
  struct sigaction sact;
  int counter;

  sigemptyset(&sact.sa_mask);
  sact.sa_flags = SA_SIGINFO;
  sact.sa_sigaction = catcher;
  sigaction(SIGALRM, &sact, NULL);

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

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
