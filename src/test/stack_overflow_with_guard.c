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

int main(int argc, __attribute__((unused)) char* argv[]) {
  pid_t child;
  int status;

  size_t page_size = sysconf(_SC_PAGESIZE);
  depth = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
               MAP_ANONYMOUS | MAP_SHARED, -1, 0);
  test_assert(depth != MAP_FAILED);

  child = fork();

  if (!child) {
    struct sigaction act;
    int* fake_sp = &argc;

    act.sa_sigaction = SEGV_handler;
    act.sa_flags = SA_SIGINFO;
    sigemptyset(&act.sa_mask);
    test_assert(0 == sigaction(SIGSEGV, &act, NULL));

    void* p =
        (void*)((size_t)(fake_sp - 8 * page_size) & ~(size_t)(page_size - 1));

    test_assert(mmap(p, page_size, PROT_NONE,
                     MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0) == p);

    return recurse();
  }

  test_assert(wait(&status) == child);
  test_assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGSEGV);

  atomic_printf("depth = %d\n", *depth);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
