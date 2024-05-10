/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  size_t page_size = sysconf(_SC_PAGESIZE);

  for (int i = 0; i < 2; ++i) {
    char* p = (char*)mmap(NULL, 5*page_size, PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | (i ? MAP_SHARED : MAP_PRIVATE), -1, 0);
    test_assert(p != MAP_FAILED);
    munmap(p + 3*page_size, page_size);

    int ret = prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, p + page_size, page_size, "abc");
    if (ret < 0 && errno == EINVAL) {
      atomic_puts("PR_SET_VMA_ANON_NAME not supported, skipping test");
      atomic_puts("EXIT-SUCCESS");
      return 0;
    }
    test_assert(ret == 0);

    ret = prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, p + page_size, page_size*3, "def");
    test_assert(ret == -1 && errno == ENOMEM);

    ret = prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, p + page_size, page_size*3, "$$$");
    test_assert(ret == -1 && errno == EINVAL);

    ret = prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, p + page_size, page_size*3, "");
    test_assert(ret == -1 && errno == ENOMEM);

    ret = prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, p + page_size, page_size*2, NULL);
    test_assert(ret == 0);

    int fd = open("/proc/self/exe", O_RDONLY);
    test_assert(fd >= 0);
    char* p2 = mmap(p + 3*page_size, page_size, PROT_READ, MAP_FIXED | MAP_PRIVATE, fd, 0);
    test_assert(p2 != MAP_FAILED);
    ret = prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, p, page_size*4, "ghi");
    test_assert(ret == -1 && errno == EBADF);
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
