/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

static void clear(unsigned char* p) {
  size_t i;
  for (i = 0; i < (unsigned) PAGE_SIZE; ++i) {
    p[i] = i & 0xFF;
  }
}

int main(void) {
  unsigned char* p = (unsigned char*)mmap(NULL, PAGE_SIZE * 2, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  struct iovec in_iov[2];
  struct iovec out_iov[2];

  test_assert(p != MAP_FAILED);
  test_assert(0 == munmap(p + PAGE_SIZE, PAGE_SIZE));

  in_iov[0].iov_base = p;
  in_iov[0].iov_len = 2;
  in_iov[1].iov_base = p + 3;
  in_iov[1].iov_len = 3;
  out_iov[0].iov_base = p + PAGE_SIZE - 6;
  out_iov[0].iov_len = 3;
  out_iov[1].iov_base = p + PAGE_SIZE - 1;
  out_iov[1].iov_len = 2;

  clear(p);
  test_assert(4 == process_vm_readv(getpid(), out_iov, 2, in_iov, 2, 0));
  test_assert(out_iov[1].iov_len == 2);
  test_assert(p[PAGE_SIZE - 7] == ((PAGE_SIZE - 7) & 0xff));
  test_assert(p[PAGE_SIZE - 6] == 0);
  test_assert(p[PAGE_SIZE - 5] == 1);
  test_assert(p[PAGE_SIZE - 4] == 3);
  test_assert(p[PAGE_SIZE - 3] == ((PAGE_SIZE - 3) & 0xff));
  clear(p);
  test_assert(4 == process_vm_writev(getpid(), in_iov, 2, out_iov, 2, 0));
  test_assert(out_iov[1].iov_len == 2);
  test_assert(p[PAGE_SIZE - 7] == ((PAGE_SIZE - 7) & 0xff));
  test_assert(p[PAGE_SIZE - 6] == 0);
  test_assert(p[PAGE_SIZE - 5] == 1);
  test_assert(p[PAGE_SIZE - 4] == 3);
  test_assert(p[PAGE_SIZE - 3] == ((PAGE_SIZE - 3) & 0xff));

  out_iov[1].iov_base = p + PAGE_SIZE - 2;
  out_iov[1].iov_len = 3;

  clear(p);
  test_assert(5 == process_vm_readv(getpid(), out_iov, 2, in_iov, 2, 0));
  test_assert(p[PAGE_SIZE - 7] == ((PAGE_SIZE - 7) & 0xff));
  test_assert(p[PAGE_SIZE - 6] == 0);
  test_assert(p[PAGE_SIZE - 5] == 1);
  test_assert(p[PAGE_SIZE - 4] == 3);
  test_assert(p[PAGE_SIZE - 3] == ((PAGE_SIZE - 3) & 0xff));
  test_assert(p[PAGE_SIZE - 2] == 4);
  test_assert(p[PAGE_SIZE - 1] == 5);
  clear(p);
  test_assert(5 == process_vm_writev(getpid(), in_iov, 2, out_iov, 2, 0));
  test_assert(p[PAGE_SIZE - 7] == ((PAGE_SIZE - 7) & 0xff));
  test_assert(p[PAGE_SIZE - 6] == 0);
  test_assert(p[PAGE_SIZE - 5] == 1);
  test_assert(p[PAGE_SIZE - 4] == 3);
  test_assert(p[PAGE_SIZE - 3] == ((PAGE_SIZE - 3) & 0xff));
  test_assert(p[PAGE_SIZE - 2] == 4);
  test_assert(p[PAGE_SIZE - 1] == 5);

  in_iov[0].iov_base = p + PAGE_SIZE - 1;
  in_iov[0].iov_len = 2;
  out_iov[0].iov_base = p;
  out_iov[0].iov_len = 3;

  clear(p);
  test_assert(1 == process_vm_readv(getpid(), out_iov, 1, in_iov, 1, 0));
  test_assert(p[0] == ((PAGE_SIZE - 1) & 0xff));
  test_assert(p[1] == 1);
  clear(p);
  test_assert(1 == process_vm_writev(getpid(), in_iov, 1, out_iov, 1, 0));
  test_assert(p[0] == ((PAGE_SIZE - 1) & 0xff));
  /* Linux kernel bug: should be 1, but sometimes is zero ---
     extra data written. https://bugzilla.kernel.org/show_bug.cgi?id=113541 */
  if (p[1] == 0) {
    atomic_puts("Kernel bug detected!");
  }
  test_assert(p[1] == 1 || p[1] == 0);

  in_iov[0].iov_base = p + PAGE_SIZE - 4;
  in_iov[0].iov_len = 2;
  in_iov[1].iov_base = p + PAGE_SIZE - 2;
  in_iov[1].iov_len = 3;
  out_iov[0].iov_base = p;
  out_iov[0].iov_len = 1;
  out_iov[1].iov_base = p + 2;
  out_iov[1].iov_len = 4;

  clear(p);
  test_assert(4 == process_vm_readv(getpid(), out_iov, 2, in_iov, 2, 0));
  test_assert(p[0] == ((PAGE_SIZE - 4) & 0xff));
  test_assert(p[1] == 1);
  test_assert(p[2] == ((PAGE_SIZE - 3) & 0xff));
  test_assert(p[3] == ((PAGE_SIZE - 2) & 0xff));
  test_assert(p[4] == ((PAGE_SIZE - 1) & 0xff));
  test_assert(p[5] == 5);
  clear(p);
  test_assert(4 == process_vm_writev(getpid(), in_iov, 2, out_iov, 2, 0));
  test_assert(p[0] == ((PAGE_SIZE - 4) & 0xff));
  test_assert(p[1] == 1);
  test_assert(p[2] == ((PAGE_SIZE - 3) & 0xff));
  test_assert(p[3] == ((PAGE_SIZE - 2) & 0xff));
  test_assert(p[4] == ((PAGE_SIZE - 1) & 0xff));
  if (p[5] == 0) {
    atomic_puts("Kernel bug detected!");
  }
  test_assert(p[5] == 5 || p[5] == 0);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
