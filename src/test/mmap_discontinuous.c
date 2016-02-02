/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

static int create_segment(size_t num_bytes) {
  char filename[] = "/dev/shm/rr-test-XXXXXX";
  int fd = mkstemp(filename);
  unlink(filename);
  test_assert(fd >= 0);
  ftruncate(fd, num_bytes);
  return fd;
}

int main(void) {
  ssize_t page_size = sysconf(_SC_PAGESIZE);
  int fd = create_segment(3 * page_size);

  uint8_t* wpage1 = mmap(NULL, page_size, PROT_WRITE, MAP_SHARED, fd, 0);
  uint8_t* wpage2 =
      mmap(NULL, page_size, PROT_WRITE, MAP_SHARED, fd, 2 * page_size);

  test_assert(wpage1 != (void*)-1 && wpage2 != (void*)-1);
  test_assert(wpage1 != wpage2);
  test_assert(wpage2 - wpage1 == page_size || wpage1 - wpage2 == page_size);

  wpage1 =
      mmap(NULL, page_size, PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  wpage2 = mmap(NULL, page_size, PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1,
                2 * page_size);

  test_assert(wpage1 != (void*)-1 && wpage2 != (void*)-1);
  test_assert(wpage1 != wpage2);
  test_assert(wpage2 - wpage1 == page_size || wpage1 - wpage2 == page_size);

  atomic_puts("EXIT-SUCCESS");

  return 0;
}
