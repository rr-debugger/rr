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

static long set_mempolicy(int mode, const unsigned long* nodemask,
                          unsigned long maxnode) {
  return syscall(SYS_set_mempolicy, mode, nodemask, maxnode);
}

static int get_mempolicy(int* mode, unsigned long* nodemask,
                         unsigned long maxnode, void* addr,
                         unsigned long flags) {
  return syscall(SYS_get_mempolicy, mode, nodemask, maxnode, addr, flags);
}

int main(void) {
  size_t page_size = sysconf(_SC_PAGESIZE);
  void* p = mmap(NULL, 16 * page_size, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  int ret;

  test_assert(p != MAP_FAILED);
  ret = mbind(p, 16 * page_size, MPOL_PREFERRED, NULL, 0, MPOL_MF_MOVE);
  test_assert(ret == 0 || (ret == -1 && errno == ENOSYS));

  // sanity check
  ret = set_mempolicy(0, NULL, 0);
  test_assert(ret == 0);
  ret = get_mempolicy(NULL, NULL, 0, NULL, 0);
  test_assert(ret == 0);

  // test in and out params
  // Make `nodemask` big in case we run on a kernel that has MAX_NUMNODES set
  // to a large value; we get EINVAL if we pass a maxnodes value that's too
  // small. And there's no way to determine what MAX_NUMNODES is AFAIK. What
  // a terrible API!
  unsigned long nodemask[64] = { 0x1 };
  ret = set_mempolicy(MPOL_BIND, nodemask, 8 * sizeof(unsigned long));
  test_assert(ret == 0);
  int mode;
  memset(nodemask, 0xff, sizeof(nodemask));
  ret = get_mempolicy(&mode, nodemask, 8 * sizeof(nodemask), NULL, 0);
  if (ret < 0) {
    test_assert(errno == EINVAL);
  } else {
    test_assert(mode == MPOL_BIND);
    test_assert(nodemask[0] == 0x1);
    test_assert(nodemask[1] == 0);
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
