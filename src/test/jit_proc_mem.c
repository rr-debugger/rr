/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */
#define _FILE_OFFSET_BITS 64

#include "util.h"
#include <stdlib.h>

typedef int (*puts_func)(const char* fmt);

int template_function(puts_func f, char* text) {
  f(text);
  return 0;
}

static __attribute__((noinline)) void breakpoint(void) {
  int break_here = 1;
  (void)break_here;
}

extern char __etext; // end of text section
int main(void) {
  void* space = mmap(NULL, 4096, PROT_EXEC | PROT_READ,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  int memfd = open("/proc/self/mem", O_RDWR);
  breakpoint();

  // It doesn't matter if we copy more than template_function, we just
  // shouldn't fall off the end of the text section.
  size_t nbytes = (uintptr_t)&__etext - (uintptr_t)template_function;
  ssize_t to_write = nbytes > 4096 ? 4096 : nbytes;
  int nwritten =
      pwrite(memfd, (void*)template_function, to_write, (uintptr_t)space);
  test_assert(to_write == nwritten);

  int ret = ((int (*)(puts_func, char*))space)(atomic_puts, "EXIT-SUCCESS");
  breakpoint();
  return ret;
}
