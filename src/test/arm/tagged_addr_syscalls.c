/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#include <linux/prctl.h>
#include <sys/prctl.h>

/* With the tagged address ABI, the kernel ignores the tag in the top byte of
   the pointers that syscalls access. readv() can block, so rr would make it
   use scratch memory; pipe2() and getcwd() can't. rr accesses tracee memory
   through /proc/<pid>/mem, where an address with a tag of 0x80 or above is a
   negative offset, so we test those tags too. mprotect() ignores the tag
   too, so rr must know that a page made writable through a tagged pointer
   is writable. */

static const uintptr_t tags[] = { 0x2a, 0x80, 0xff };

static void* tagged(void* p, uintptr_t tag) {
  return (void*)(((uintptr_t)p & ((UINT64_C(1) << 56) - 1)) | (tag << 56));
}

static void check_tag(uintptr_t tag) {
  int fds[2];
  int tagged_fds[2] = { -1, -1 };
  char buf[16];
  char cwd[PATH_MAX];
  char tagged_cwd[PATH_MAX];
  struct iovec iov;
  size_t page_size = sysconf(_SC_PAGESIZE);
  char* page;

  test_assert(0 == pipe(fds));
  test_assert(5 == write(fds[1], "hello", 5));
  memset(buf, 0, sizeof(buf));
  iov.iov_base = tagged(buf, tag);
  iov.iov_len = sizeof(buf);
  test_assert(5 == readv(fds[0], &iov, 1));
  test_assert(!memcmp(buf, "hello", 5));
  test_assert(0 == close(fds[0]));
  test_assert(0 == close(fds[1]));

  test_assert(0 == pipe2(tagged(tagged_fds, tag), 0));
  test_assert(tagged_fds[0] >= 0 && tagged_fds[1] >= 0);
  test_assert(1 == write(tagged_fds[1], "x", 1));
  test_assert(1 == read(tagged_fds[0], buf, 1));
  test_assert(buf[0] == 'x');
  test_assert(0 == close(tagged_fds[0]));
  test_assert(0 == close(tagged_fds[1]));

  test_assert(getcwd(cwd, sizeof(cwd)) != NULL);
  memset(tagged_cwd, 0, sizeof(tagged_cwd));
  test_assert(getcwd(tagged(tagged_cwd, tag), sizeof(tagged_cwd)) != NULL);
  test_assert(!strcmp(cwd, tagged_cwd));

  page = mmap(NULL, page_size, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  test_assert(page != MAP_FAILED);
  test_assert(0 ==
              mprotect(tagged(page, tag), page_size, PROT_READ | PROT_WRITE));
  test_assert(0 == pipe(fds));
  test_assert(5 == write(fds[1], "hello", 5));
  iov.iov_base = tagged(page, tag);
  iov.iov_len = page_size;
  test_assert(5 == readv(fds[0], &iov, 1));
  test_assert(!memcmp(page, "hello", 5));
  test_assert(0 == close(fds[0]));
  test_assert(0 == close(fds[1]));
  test_assert(0 == munmap(tagged(page, tag), page_size));
}

int main(void) {
  size_t i;
  int ret;

  ret = prctl(PR_SET_TAGGED_ADDR_CTRL, PR_TAGGED_ADDR_ENABLE, 0, 0, 0);
  if (ret == -1 && errno == EINVAL) {
    atomic_puts("Tagged address ABI not supported, skipping test");
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }
  test_assert(ret == 0);

  for (i = 0; i < sizeof(tags) / sizeof(tags[0]); ++i) {
    check_tag(tags[i]);
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
