/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void sighandler(int sig) {
  atomic_printf("caught signal %d, exiting\n", sig);
  _exit(0);
}

int main(void) {
  char* invalid_jump_here;
  size_t page_size = sysconf(_SC_PAGESIZE);

  invalid_jump_here = (char*)mmap(NULL, page_size, PROT_NONE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  test_assert(invalid_jump_here != MAP_FAILED);

  // Just for clean exit to not worry people running the test manually ;).
  signal(SIGSEGV, sighandler);
  ((void (*)(void))invalid_jump_here)();
  test_assert(0 && "Shouldn't reach here");
}
