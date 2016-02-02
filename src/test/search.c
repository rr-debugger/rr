/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

char buf[1024] = { 99, 1, 2, 2, 3, 0 };
char* p;
char* p_end;
int* argc_ptr;

static void breakpoint(void) {}

int main(int argc, __attribute__((unused)) char* argv[]) {
  /* 'buf' could be mapped twice in our address space, once in our data segment
     and once in the text segment. Tests that search the whole address space for
     the contents of 'buf' don't want to find a spurious match in .text, so
     setup buf with its intended contents here. After this the copy in .text
     should continue to map the old value. */
  buf[0] = 0;

  argc_ptr = &argc;

  p = (char*)mmap(NULL, PAGE_SIZE * 4, PROT_READ | PROT_WRITE,
                  MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  test_assert(p != MAP_FAILED);
  p_end = p + PAGE_SIZE * 4;

  memcpy(p + PAGE_SIZE, buf, sizeof(buf));
  memcpy(p + PAGE_SIZE * 2, buf, sizeof(buf));

  test_assert(0 == munmap(p, PAGE_SIZE));
  test_assert(0 == munmap(p + PAGE_SIZE * 3, PAGE_SIZE));
  test_assert(0 == mprotect(p + PAGE_SIZE, PAGE_SIZE, PROT_NONE));

  breakpoint();

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
