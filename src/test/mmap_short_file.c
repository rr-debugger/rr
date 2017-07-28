/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#define DUMMY_FILE "dummy.txt"

static void sighandler(int sig) {
  atomic_printf("caught signal %d, exiting\n", sig);
  atomic_puts("EXIT-SUCCESS");
  _exit(0);
}

int main(void) {
  size_t page_size = sysconf(_SC_PAGESIZE);
  int fd = open(DUMMY_FILE, O_CREAT | O_EXCL | O_RDWR, 0600);
  int one = 1;
  int* rpage;

  unlink(DUMMY_FILE);

  test_assert(fd >= 0);
  test_assert(sizeof(one) == write(fd, &one, sizeof(one)));

  rpage = mmap(NULL, page_size * 2, PROT_READ, MAP_PRIVATE, fd, 0);
  test_assert(rpage != (void*)-1);
  test_assert(*rpage == 1);

  signal(SIGSEGV, sighandler);
  signal(SIGBUS, sighandler);
  /* This should generate a SIGBUS, but the test will pass whether the
     kernel generates SIGBUS or SIGSEGV.
     rr checks that the same signal is produced during replay
     as during recording. */
  char ch = *((char*)rpage + page_size);

  atomic_printf("FAILED: no segfault, read %d", ch);
  return 0;
}
