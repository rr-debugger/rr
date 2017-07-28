/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static char* volatile end_of_guard_addr;
static volatile char got_segv;

static void handler(__attribute__((unused)) int sig) {
  size_t page_size = sysconf(_SC_PAGESIZE);
  test_assert(end_of_guard_addr ==
              mmap(end_of_guard_addr, page_size, PROT_READ | PROT_WRITE,
                   MAP_ANONYMOUS | MAP_FIXED | MAP_PRIVATE, -1, 0));
  got_segv = 1;
}

int main(void) {
  int local_var;
  size_t page_size = sysconf(_SC_PAGESIZE);
  char* guard_addr =
      (char*)(((uintptr_t)&local_var) & ~((uintptr_t)page_size - 1)) -
      262 * page_size;
  int i;
  test_assert(guard_addr == mmap(guard_addr, page_size * 128, PROT_NONE,
                                 MAP_ANONYMOUS | MAP_FIXED | MAP_PRIVATE, -1,
                                 0));
  end_of_guard_addr = guard_addr + page_size * 128;
  atomic_printf("guard_addr=%p end_of_guard_addr=%p\n", guard_addr,
                end_of_guard_addr);

  /* Extend mapping close to the actual address we want to test. */
  for (i = 127; i >= 5; --i) {
    end_of_guard_addr[page_size * i] = 77;
  }

  signal(SIGSEGV, handler);
  /* This should cause a SEGV since we should not be able to extend the stack
     to make it adjacent to our guard page.
     The handler should fire and unmap the guard page so the write can
     succeed. */
  end_of_guard_addr[0] = 77;
  test_assert(got_segv);
  test_assert(end_of_guard_addr[0] == 77);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
