/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  size_t page_size = sysconf(_SC_PAGESIZE);
  int fd;
  void* map_addr;
  long end;

  /* Map a file that's (probably) not in a tmpfs */
  fd = open("/bin/ls", O_RDONLY);
  end = lseek(fd, 0, SEEK_END);
  test_assert(end > 0);
  map_addr = mmap(NULL, ceil_page_size(end) + page_size, PROT_READ, MAP_PRIVATE, fd, 0);
  test_assert(MAP_FAILED != map_addr);
  test_assert(MAP_FAILED != mmap(map_addr, page_size, PROT_READ,
                                 MAP_PRIVATE | MAP_FIXED, fd, 0));
  map_addr = mremap(map_addr, ceil_page_size(end) + page_size,
                    ceil_page_size(end) + page_size*2, MREMAP_MAYMOVE);
  if (map_addr == MAP_FAILED && errno == EFAULT) {
    // This happens in a Debian 9 kernel (4.9.0-11-amd64)
    atomic_puts("Kernel didn't coalesce the mapping; skipping test");
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }
  test_assert(MAP_FAILED != map_addr);

  /* Try again, shrinking this time */
  fd = open("/bin/ls", O_RDONLY);
  end = lseek(fd, 0, SEEK_END);
  test_assert(end > 0);
  map_addr = mmap(NULL, ceil_page_size(end) + page_size*3, PROT_READ, MAP_PRIVATE, fd, 0);
  test_assert(MAP_FAILED != map_addr);
  test_assert(MAP_FAILED != mmap(map_addr, page_size, PROT_READ,
                                 MAP_PRIVATE | MAP_FIXED, fd, 0));
  map_addr = mremap(map_addr, ceil_page_size(end) + page_size*2,
                    ceil_page_size(end) + page_size, 0);
  test_assert(MAP_FAILED != map_addr);

  /* Try again, this time starting in the middle of a mapping */
  fd = open("/bin/ls", O_RDONLY);
  end = lseek(fd, 0, SEEK_END);
  test_assert(end > 0);
  map_addr = mmap(NULL, ceil_page_size(end) + page_size*3, PROT_READ, MAP_PRIVATE, fd, 0);
  test_assert(MAP_FAILED != map_addr);
  test_assert(MAP_FAILED != mmap(map_addr, page_size*3, PROT_READ,
                                 MAP_PRIVATE | MAP_FIXED, fd, 0));
  map_addr = mremap(map_addr + page_size, page_size*3, page_size, 0);
  test_assert(MAP_FAILED != map_addr);

  atomic_puts("EXIT-SUCCESS");

  return 0;
}
