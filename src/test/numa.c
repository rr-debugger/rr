/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

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

static long set_mempolicy(int mode, const unsigned long* nodemask,
                          unsigned long maxnode) {
  return syscall(SYS_set_mempolicy, mode, nodemask, maxnode);
}

static int get_mempolicy(int* mode, unsigned long* nodemask,
                         unsigned long maxnode, void* addr,
                         unsigned long flags) {
  return syscall(SYS_get_mempolicy, mode, nodemask, maxnode, addr, flags);
}

typedef struct { unsigned long m[64]; } Nodemask;
typedef struct { uint32_t m[4]; } Nodemask128Bits;

int main(void) {
  size_t page_size = sysconf(_SC_PAGESIZE);
  void* p = mmap(NULL, 16 * page_size, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  int ret;
  Nodemask* nodemask;
  Nodemask128Bits* nodemask128;
  unsigned long mask = 0x1;
  int mode;

  test_assert(p != MAP_FAILED);
  ret = mbind(p, 16 * page_size, MPOL_PREFERRED, NULL, 0, MPOL_MF_MOVE);
  test_assert(ret == 0 || (ret == -1 && errno == ENOSYS));

  // sanity check
  ret = set_mempolicy(0, NULL, 0);
  test_assert(ret == 0 || (ret == -1 && errno == ENOSYS));
  ret = get_mempolicy(NULL, NULL, 0, NULL, 0);
  test_assert(ret == 0 || (ret == -1 && errno == ENOSYS));

  // test in and out params
  // Make `nodemask` big in case we run on a kernel that has MAX_NUMNODES set
  // to a large value; we get EINVAL if we pass a maxnodes value that's too
  // small. And there's no way to determine what MAX_NUMNODES is AFAIK. What
  // a terrible API!
  ret = set_mempolicy(MPOL_BIND, &mask, 8 * sizeof(mask));
  test_assert(ret == 0 || (ret == -1 && errno == ENOSYS));
  ALLOCATE_GUARD(nodemask, 'a');
  ret = get_mempolicy(&mode, nodemask->m, 8 * sizeof(nodemask->m), NULL, 0);
  if (ret < 0) {
    test_assert(errno == EINVAL || errno == ENOSYS);
  } else {
    test_assert(mode == MPOL_BIND);
    test_assert(nodemask->m[0] == 0x1);
    test_assert(nodemask->m[1] == 0);
  }
  VERIFY_GUARD(nodemask);

  // With maxnode 96 and at most 96 possible nodes, the kernel writes 128
  // bits of the nodemask, also for 32-bit tasks: it zeroes the bits past
  // its own nodemask up to a 64-bit boundary. A 64-bit kernel without
  // https://github.com/torvalds/linux/commit/e130242dc351f1cfa2bbeb6766a1486ce936ef88
  // leaves the last 32 bits alone for 32-bit tasks.
  ALLOCATE_GUARD(nodemask128, -1);
  ret = get_mempolicy(&mode, (unsigned long*)nodemask128->m, 96, NULL, 0);
  if (ret < 0) {
    test_assert(errno == EINVAL || errno == ENOSYS);
  } else {
    test_assert(mode == MPOL_BIND);
    test_assert(nodemask128->m[0] == 0x1);
    test_assert(nodemask128->m[1] == 0);
    test_assert(nodemask128->m[2] == 0);
    test_assert(nodemask128->m[3] == 0 || nodemask128->m[3] == 0xffffffff);
  }
  VERIFY_GUARD(nodemask128);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
