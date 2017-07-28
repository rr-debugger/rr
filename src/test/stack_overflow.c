/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static int* depth;

static int recurse(void) {
  int result;
  ++*depth;
  if (*depth > 10000000) {
    return 3;
  }
  result = recurse() * 13 + 1;
  --*depth;
  return result;
}

static void SEGV_handler(__attribute__((unused)) int sig,
                         __attribute__((unused)) siginfo_t* si,
                         __attribute__((unused)) void* context) {
  atomic_puts(
      "Should not reach SEGV handler, since there's no safe altstack to use");
  exit(1);
}

int main(void) {
  pid_t child;
  int status;

  size_t page_size = sysconf(_SC_PAGESIZE);
  depth = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
               MAP_ANONYMOUS | MAP_SHARED, -1, 0);
  test_assert(depth != MAP_FAILED);

  child = fork();

  if (!child) {
    /* Testing shows that the output value of |depth| is not very sensitive to
       small values of the limit, but it's very sensitive around the 500K mark.
    */
    struct rlimit r = { 500000, 500000 };
    struct sigaction act;

    act.sa_sigaction = SEGV_handler;
    act.sa_flags = SA_SIGINFO;
    sigemptyset(&act.sa_mask);
    test_assert(0 == sigaction(SIGSEGV, &act, NULL));

    test_assert(0 == setrlimit(RLIMIT_STACK, &r));

    return recurse();
  }

  atomic_printf("child %d\n", child);
  test_assert(wait(&status) == child);
  test_assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGSEGV);

  atomic_printf("depth = %d\n", *depth);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
