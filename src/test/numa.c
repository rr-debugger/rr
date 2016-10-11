/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

#define MPOL_DEFAULT 0
#define MPOL_PREFERRED 1
#define MPOL_BIND 2
#define MPOL_INTERLEAVE 3

#define MPOL_MF_STRICT 0x1
#define MPOL_MF_MOVE 0x2
#define MPOL_MF_MOVE_ALL 0x4

#define MPOL_F_STATIC_NODES (1 << 15)
#define MPOL_F_RELATIVE_NODES (1 << 14)

static long mbind(void* start, unsigned long len, int mode,
                  const unsigned long* nmask, unsigned long maxnode,
                  unsigned flags) {
  return syscall(SYS_mbind, start, len, mode, nmask, maxnode, flags);
}

int main(void) {
  size_t page_size = sysconf(_SC_PAGESIZE);
  void* p = mmap(NULL, 16 * page_size, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  int ret;

  test_assert(p != MAP_FAILED);
  ret = mbind(p, 16 * page_size, MPOL_PREFERRED, NULL, 0, MPOL_MF_MOVE);
  test_assert(ret == 0 || (ret == -1 && errno == ENOSYS));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
