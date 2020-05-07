/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

// Global to protecte them from the compiler potentially
// smashing them, thinking they're unused
volatile int fd;
volatile void* buf;
volatile int counter;
volatile int counter2 = 0;

int main(void) {
  size_t page_size = sysconf(_SC_PAGESIZE);
  int scratch_size = 512 * page_size;
  fd = open("tempfile", O_RDWR | O_CREAT | O_TRUNC, 0700);
  buf = mmap(NULL, scratch_size, PROT_READ | PROT_WRITE,
                   MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  test_assert(fd >= 0);

  /* First, initialize the file, so the syscall buffer will attempt to
     clone it in each thread */
  int ret = write(fd, (void*)buf, scratch_size);
  test_assert(ret == scratch_size);

  for (counter = 0; counter < 20; ++counter) {
    // Make sure the clone fd ends up having a different number in each task
    open("/dev/null", O_RDONLY);
    if (!vfork()) {
      continue;
    }
    atomic_printf("child %d\n", getpid());
    ret = lseek(fd, 0, SEEK_SET);
    test_assert(ret == 0);
    ret = read(fd, (void*)buf, scratch_size);
    test_assert(ret == scratch_size);
    if (++counter2 == counter) {
      atomic_puts("EXIT-SUCCESS");
    }
    _exit(0);
    break;
  }
  _exit(0);
}
