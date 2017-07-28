/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* Make buf weird so that when we search the whole address space,
   we don't find any accidental matches.
*/
char buf[1024] = { 99, 1, 2, 2, 3, 0xff, 0xfa, 0xde, 0xbc };
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

  size_t page_size = sysconf(_SC_PAGESIZE);
  p = (char*)mmap(NULL, page_size * 4, PROT_READ | PROT_WRITE,
                  MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  test_assert(p != MAP_FAILED);
  p_end = p + page_size * 4;

  /* Don't copy the whole buf. If we do, we may trigger memcpy routines
   * that copy state to registers which are later spilled to the stack,
   * causing false positives. These short memcpys are performed using volatile
   * registers.
   */
  memcpy(p + page_size, buf, 12);
  memcpy(p + page_size * 2, buf, 12);

  test_assert(0 == munmap(p, page_size));
  test_assert(0 == munmap(p + page_size * 3, page_size));
  test_assert(0 == mprotect(p + page_size, page_size, PROT_NONE));

  breakpoint();

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
