/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void handler(__attribute__((unused)) int sig) {
  write(1, "EXIT-SUCCESS\n", 13);
  _exit(0);
}

static int do_thread(__attribute__((unused)) void* p) {
  /* Enter a signal handler at the top of our thread stack.
     rr's estimate of the sighandler frame size will spill beyond the
     thread stack. */
  signal(SIGSEGV, handler);
  *(volatile char*)0 = 0;
  test_assert(0 && "Should not be reached");
  return 0;
}

int main(void) {
  size_t page_size = sysconf(_SC_PAGESIZE);
  size_t stack_len = page_size * 8;
  int fd;
  int ret;
  char* p = (char*)mmap(NULL, stack_len + page_size, PROT_READ | PROT_WRITE,
    MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  test_assert(p != MAP_FAILED);

  /* Map a readonly trace page immediately after our thread stack */
  fd = open("/bin/ls", O_RDONLY);
  test_assert(fd >= 0);
  munmap(p + stack_len, page_size);
  char* pp = (char*)mmap(p + stack_len, page_size, PROT_NONE, MAP_SHARED, fd, 0);
  test_assert(pp == p + stack_len);

  ret = clone(do_thread, p + stack_len, CLONE_THREAD | CLONE_SIGHAND | CLONE_VM, NULL);
  test_assert(ret >= 0);

  sleep(1000);
  return 0;
}
