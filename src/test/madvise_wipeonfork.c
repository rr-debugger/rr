/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#ifndef MADV_WIPEONFORK
#define MADV_WIPEONFORK 18
#endif

#ifndef MADV_KEEPONFORK
#define MADV_KEEPONFORK 19
#endif

int main(void) {
  char* page;
  pid_t pid;
  int status;

  size_t page_size = sysconf(_SC_PAGESIZE);
  page = mmap(NULL, page_size * 4, PROT_READ | PROT_WRITE,
              MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  test_assert(page != MAP_FAILED);

  if (0 != madvise(page, 4 * page_size, MADV_WIPEONFORK)) {
    atomic_puts("MADV_WIPEONFORK not supported, skipping test.");
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }

  test_assert(0 == madvise(page + page_size, page_size, MADV_KEEPONFORK));
  test_assert(0 == madvise(page + 3 * page_size, page_size, MADV_KEEPONFORK));

  page[0] = 1;
  page[page_size] = 1;
  page[2 * page_size] = 1;
  page[3 * page_size] = 1;

  pid = fork();
  if (!pid) {
    test_assert(page[0] == 0);
    test_assert(page[page_size] == 1);
    test_assert(page[2 * page_size] == 0);
    test_assert(page[3 * page_size] == 1);

    atomic_puts("EXIT-SUCCESS");
    return 77;
  }

  test_assert(pid == wait(&status));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);

  test_assert(0 == madvise(page, 4 * page_size, MADV_DONTFORK));
  test_assert(0 == madvise(page, 2 * page_size, MADV_DOFORK));

  pid = fork();
  if (!pid) {
    // This should still be zero, because DONTFORK and WIPEONFORK are tracked
    // separately in the kernel.
    test_assert(page[0] == 0);
    test_assert(page[page_size] == 1);
    test_assert(page[2 * page_size] == 1); // This should segfault.

    atomic_puts("FAILED: the third page should have been removed.");
    return -4;
  }

  test_assert(pid == wait(&status));
  test_assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGSEGV);

  return 0;
}
