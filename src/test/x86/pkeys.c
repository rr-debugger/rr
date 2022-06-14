/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#ifdef PKEY_DISABLE_ACCESS
enum cpuid_requests {
  CPUID_GETEXTENDEDFEATURES = 0x07,
};

static void cpuid(int code, int subrequest, unsigned int* a, unsigned int* c,
                  unsigned int* d) {
  asm volatile("cpuid"
               : "=a"(*a), "=c"(*c), "=d"(*d)
               : "a"(code), "c"(subrequest)
               : "ebx");
}

static unsigned int rdpkru(void) {
  unsigned int eax;
  unsigned int ecx = 0;

  asm volatile(".byte 0x0f,0x01,0xee\n\t"
               : "=a" (eax) : "c" (ecx) : "edx");
  return eax;
}

static void wrpkru(unsigned int pkru) {
  unsigned int eax = pkru;
  unsigned int ecx = 0;
  unsigned int edx = 0;

  asm volatile(".byte 0x0f,0x01,0xef\n\t"
               : : "a" (eax), "c" (ecx), "d" (edx));
}

static char* p;

static void unset_pkey(__attribute__((unused)) int sig) {
  syscall(SYS_pkey_mprotect, p, 4096, PROT_READ | PROT_WRITE, 0);
}

int main(void) {
  unsigned int eax, ecx, edx;
  cpuid(CPUID_GETEXTENDEDFEATURES, 0, &eax, &ecx, &edx);
  if (!(ecx & (1 << 3))) {
    // PKU not present.
    atomic_puts("pkeys not supported on this system, skipping");
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }

  unsigned int initial_pkru = rdpkru();
  test_assert(initial_pkru == 0x55555554);
  int pkey = syscall(SYS_pkey_alloc, 0, 0);
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
  unsigned int modified_pkru = rdpkru();
  test_assert(initial_pkru == (modified_pkru | PKEY_DISABLE_ACCESS << (2 * pkey)));
  test_assert((initial_pkru & ~(PKEY_DISABLE_ACCESS << (2 * pkey ))) == modified_pkru);

  p = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  test_assert(p != MAP_FAILED);
  ret = syscall(SYS_pkey_mprotect, p, 4096, PROT_READ | PROT_WRITE, pkey);
  test_assert(ret == 0);
  p[0] = 1;

  wrpkru(PKEY_DISABLE_ACCESS << (2 * pkey));
  signal(SIGSEGV, unset_pkey);
  p[0] = 2;

  ret = syscall(SYS_pkey_free, pkey);
  test_assert(ret == 0);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
#else
int main(void) {
  atomic_puts("pkeys not supported on the machine compiling this test, skipping");
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
#endif
