/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void wrpkru(unsigned int pkru) {
  unsigned int eax = pkru;
  unsigned int ecx = 0;
  unsigned int edx = 0;

  asm volatile(".byte 0x0f,0x01,0xef\n\t"
               : : "a" (eax), "c" (ecx), "d" (edx));
}

static char* p;

static void unset_pkey(__attribute__((unused)) int sig) {
  pkey_mprotect(p, 4096, PROT_READ | PROT_WRITE, 0);
}

int main(void) {
  int pkey = pkey_alloc(0, 0);
  int ret;
  if (pkey < 0 && errno == ENOSYS) {
    atomic_puts("pkeys not supported in kernel, skipping");
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }
  if (pkey < 0 && (errno == ENOSPC || errno == EINVAL)) {
    atomic_puts("pkeys not supported on this system, skipping");
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }
  test_assert(pkey >= 0);

  p = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  test_assert(p != MAP_FAILED);
  ret = pkey_mprotect(p, 4096, PROT_READ | PROT_WRITE, pkey);
  test_assert(ret == 0);
  p[0] = 1;

  wrpkru(PKEY_DISABLE_ACCESS << (2 * pkey));
  signal(SIGSEGV, unset_pkey);
  p[0] = 2;

  ret = pkey_free(pkey);
  test_assert(ret == 0);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
