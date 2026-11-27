/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

typedef int (*Func)(void);

int main(void) {
  char* p = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC,
                 MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

  if (p == MAP_FAILED && errno == EPERM) {
    atomic_puts("WX memory not supported?");
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }
  test_assert(p != MAP_FAILED);

  /* Test an instruction that modifies the next instruction */
#if defined(__i386__) || defined(__x86_64__)
  p[0] = 0xe8; // call p+5
  p[1] = 0;
  p[2] = 0;
  p[3] = 0;
  p[4] = 0;
  p[5] = 0x5b; // pop %rbx/%ebx
  /* End this fragment. */
  p[6] = 0xeb; // jmp next; next:
  p[7] = 0;
  /* Self-modifying code write to next instruction.
     This write will invalidate its own fragment and then restart the
     write instruction, so this tests that we have inserted NOP padding
     before the write instruction so it's not smashed by the patched-in
     jmp instruction. */
  p[8] = 0xc6; // mov $77,(13 - 5)(%rbx/%ebx)
  p[9] = 0x43;
  p[10] = 13 - 5;
  p[11] = 77;
  p[12] = 0xb8; // mov $66,%eax
  p[13] = 66;
  p[14] = 0;
  p[15] = 0;
  p[16] = 0;
  p[17] = 0xc3; // ret
#else
#error Unsupported architecture
#endif
  test_assert(77 == ((Func)p)());

  p[11] = 88;
  test_assert(88 == ((Func)p)());

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
