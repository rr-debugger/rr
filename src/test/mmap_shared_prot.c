/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void breakpoint(void) {}

int main(void) {
  pid_t child;
  int status;
  char* p;

  /* Do a dummy waitpid so the real one doesn't go through the linker,
     patching etc */
  waitpid(-2, NULL, 0);

  size_t page_size = sysconf(_SC_PAGESIZE);
  p = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS,
           -1, 0);
  test_assert(p != MAP_FAILED);

  *p = 'a';

  if ((child = fork()) == 0) {
    while (*(char*)p == 'a') {
      sched_yield();
    }
    return 0;
  }

  test_assert(0 == mprotect(p, page_size, PROT_READ));

  breakpoint();

  test_assert(0 == mprotect(p, page_size, PROT_READ | PROT_WRITE));

  *p = *p + 1;

  test_assert(*p == 'b');
  test_assert(child == waitpid(child, &status, 0));
  test_assert(0 == status);

  atomic_puts("EXIT-SUCCESS");

  return 0;
}
