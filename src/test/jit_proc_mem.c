/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */
#define _FILE_OFFSET_BITS 64

#include "util.h"
#include <stdlib.h>

typedef int (*puts_func)(const char* fmt);

// It's surprisingly hard to know the size of a function from C,
// even though the compiler is perfectly happy putting that information
// in the symbol table. Here we use a trick to avoid having to write
// this in assembly for every platform: We create two identical copies
// of the same function and force them into the same section. Then by
// construction, one must come after the other within a reasonable bound
// so we're guaranteed that at least one correct copy ends up where we
// want it.

#if defined(__i386__)
extern char template_function;
extern char template_function2;
// Some versions of GCC are bad at emitting calls to absolute arguments and
// still try to call __x86.get_pc_thunk.ax which won't work if we just copy
// it from the C version of the template function. Just hardcode it here.
asm("template_function:\n\t"
    "push 4(%esp)\n\t"
    "call *12(%esp)\n\t"
    "add $4,%esp\n\t"
    "xor %eax,%eax\n\t"
    "ret\n\t"
    "template_function2:\n");
#else
static int __attribute__ ((section(".text.template"))) template_function(char* text, puts_func f) {
  f(text);
  return 0;
}

static int __attribute__ ((section(".text.template"))) template_function2(char* text, puts_func f) {
  f(text);
  return 0;
}
#endif

static __attribute__((noinline)) void breakpoint(void) {
  int break_here = 1;
  (void)break_here;
}

int main(void) {
  void* space = mmap(NULL, 4096, PROT_EXEC | PROT_READ,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  int memfd = open("/proc/self/mem", O_RDWR);
  breakpoint();

  char *first = (char*)&template_function;
  char *second = (char*)&template_function2;

  if (first > second) {
    char *tmp = second;
    second = first;
    first = tmp;
  }

  ssize_t to_write = second - first;
  test_assert(to_write > 0);
  int nwritten =
      pwrite(memfd, first, to_write, (uintptr_t)space);
  test_assert(to_write == nwritten);

  int ret = ((int (*)(char*, puts_func))space)("EXIT-SUCCESS", atomic_puts);
  breakpoint();
  return ret;
}
