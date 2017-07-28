/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void sighandler(__attribute__((unused)) int sig) {
  atomic_puts("EXIT-SUCCESS");
  _exit(0);
}

int main(void) {
  size_t page_size = sysconf(_SC_PAGESIZE);
  char* p = (char*)mmap(NULL, page_size, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  test_assert(p != MAP_FAILED);

  signal(SIGSEGV, sighandler);

  *p = 'a';

  test_assert(0 == munmap(p, page_size));
  *p = 'b';

  return 0;
}
