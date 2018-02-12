/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */
#define _FILE_OFFSET_BITS 64

#include "util.h"
#include <stdlib.h>

typedef int (*puts_func)(const char* fmt);

#if defined(__x86_64__)
asm("template_function:\n\t"
    "sub $8,%rsp\n\t"
    "call *%rsi\n\t"
    "add $8,%rsp\n\t"
    "xor %eax,%eax\n\t"
    "ret\n\t"
    "template_function_end:\n");
#elif defined(__i386__)
asm("template_function:\n\t"
    "push 4(%esp)\n\t"
    "call *12(%esp)\n\t"
    "add $4,%esp\n\t"
    "xor %eax,%eax\n\t"
    "ret\n\t"
    "template_function_end:\n");
#else
#error Unknown architecture
#endif

static __attribute__((noinline)) void breakpoint(void) {
  int break_here = 1;
  (void)break_here;
}

extern char template_function;
extern char template_function_end;

int main(void) {
  void* space = mmap(NULL, 4096, PROT_EXEC | PROT_READ,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  int memfd = open("/proc/self/mem", O_RDWR);
  breakpoint();

  ssize_t to_write = &template_function_end - &template_function;
  int nwritten =
      pwrite(memfd, &template_function, to_write, (uintptr_t)space);
  test_assert(to_write == nwritten);

  int ret = ((int (*)(char*, puts_func))space)("EXIT-SUCCESS", atomic_puts);
  breakpoint();
  return ret;
}
