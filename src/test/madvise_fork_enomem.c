/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"
#include <setjmp.h>

#ifndef MADV_WIPEONFORK
#define MADV_WIPEONFORK 18
#endif

#ifndef MADV_KEEPONFORK
#define MADV_KEEPONFORK 19
#endif

/* madvise() over a range with an unmapped page applies the advice to the
   mapped pages and fails with ENOMEM. The forked child must see the
   effects of such calls, in recording and replay. */

static size_t page_size;
static sigjmp_buf jmpbuf;

static void segv_handler(__attribute__((unused)) int sig) {
  siglongjmp(jmpbuf, 1);
}

static int is_mapped(volatile char* p) {
  if (sigsetjmp(jmpbuf, 1)) {
    return 0;
  }
  (void)*p;
  return 1;
}

/* Three pages with the middle one unmapped. */
static char* map_with_hole(void) {
  char* p = mmap(NULL, 3 * page_size, PROT_READ | PROT_WRITE,
                 MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  test_assert(p != MAP_FAILED);
  test_assert(0 == munmap(p + page_size, page_size));
  p[0] = 1;
  p[2 * page_size] = 1;
  return p;
}

static void advise_with_hole(char* p, int advice) {
  test_assert(-1 == madvise(p, 3 * page_size, advice));
  test_assert(ENOMEM == errno);
}

int main(void) {
  char* dontfork;
  char* dofork;
  char* wipe;
  char* keep;
  int have_wipeonfork;
  pid_t pid;
  int status;
  int i;

  page_size = sysconf(_SC_PAGESIZE);

  dontfork = map_with_hole();
  advise_with_hole(dontfork, MADV_DONTFORK);

  dofork = map_with_hole();
  test_assert(0 == madvise(dofork, page_size, MADV_DONTFORK));
  test_assert(0 == madvise(dofork + 2 * page_size, page_size, MADV_DONTFORK));
  advise_with_hole(dofork, MADV_DOFORK);

  wipe = map_with_hole();
  keep = map_with_hole();
  have_wipeonfork = 0 == madvise(keep, page_size, MADV_WIPEONFORK);
  if (have_wipeonfork) {
    test_assert(0 ==
                madvise(keep + 2 * page_size, page_size, MADV_WIPEONFORK));
    advise_with_hole(keep, MADV_KEEPONFORK);
    advise_with_hole(wipe, MADV_WIPEONFORK);
  } else {
    atomic_puts("MADV_WIPEONFORK not supported, skipping that part.");
  }

  pid = fork();
  test_assert(pid >= 0);
  if (!pid) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = segv_handler;
    test_assert(0 == sigaction(SIGSEGV, &sa, NULL));

    for (i = 0; i < 3; i += 2) {
      test_assert(!is_mapped(dontfork + i * page_size));
      test_assert(dofork[i * page_size] == 1);
      if (have_wipeonfork) {
        test_assert(wipe[i * page_size] == 0);
        test_assert(keep[i * page_size] == 1);
      }
    }

    atomic_puts("EXIT-SUCCESS");
    return 77;
  }

  test_assert(pid == wait(&status));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);

  return 0;
}
