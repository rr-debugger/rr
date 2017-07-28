/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void check_mapping(int* page, int magic, ssize_t nr_ints) {
  int i;
  for (i = 0; i < nr_ints; ++i) {
    test_assert(page[i] == magic);
  }
  atomic_printf("  %p has the correct values\n", page);
}

int main(void) {
  size_t num_bytes = sysconf(_SC_PAGESIZE);
  int fd = open("temp", O_CREAT | O_EXCL | O_RDWR);
  int* rpage;

  unlink("temp");

  test_assert(fd >= 0);

  int magic = 0x5a5a5a5a;
  size_t i;
  for (i = 0; i < 3 * num_bytes / sizeof(magic); ++i) {
    pwrite64(fd, &magic, sizeof(magic), i * sizeof(magic));
  }

  rpage = mmap(NULL, num_bytes, PROT_READ, MAP_SHARED, fd, 0);
  atomic_printf("rpage:%p\n", rpage);
  test_assert(rpage != MAP_FAILED);

  magic = 0xa5a5a5a5;
  for (i = 0; i < num_bytes / sizeof(magic); ++i) {
    pwrite64(fd, &magic, sizeof(magic), i * sizeof(magic));
  }

  check_mapping(rpage, 0xa5a5a5a5, num_bytes / sizeof(*rpage));

  magic = 0x5a5a5a5a;
  for (i = 0; i < num_bytes / sizeof(magic); ++i) {
    pwrite64(fd, &magic, sizeof(magic), i * sizeof(magic));
  }

  check_mapping(rpage, 0x5a5a5a5a, num_bytes / sizeof(*rpage));

  magic = 0xa5a5a5a5;
  for (i = 0; i < num_bytes / sizeof(magic); ++i) {
    pwrite64(fd, &magic, sizeof(magic), num_bytes + i * sizeof(magic));
  }

  check_mapping(rpage, 0x5a5a5a5a, num_bytes / sizeof(*rpage));

  magic = 0xdeadbeef;
  pwrite64(fd, &magic, sizeof(magic), num_bytes / 2);

  test_assert(rpage[num_bytes / (sizeof(magic) * 2)] == magic);
  test_assert(rpage[0] != magic);

  pwrite64(fd, &magic, sizeof(magic), num_bytes - 2);
  test_assert(rpage[num_bytes / sizeof(magic) - 1] == (int)0xbeef5a5a);

  rpage = mremap(rpage, num_bytes, 5 * num_bytes, MREMAP_MAYMOVE);
  for (i = 3 * num_bytes / sizeof(magic); i < 5 * num_bytes / sizeof(magic);
       ++i) {
    pwrite64(fd, &magic, sizeof(magic), i * sizeof(magic));
  }
  check_mapping(&rpage[(3 * num_bytes) / sizeof(magic)], 0xdeadbeef,
                2 * num_bytes / sizeof(*rpage));

  munmap(rpage, 5 * num_bytes);

  // The case when all pages have been unmapped is special in the
  // implementation - make sure it gets sufficient coverage
  write(fd, &magic, sizeof(magic));
  write(fd, &magic, sizeof(magic));

  rpage = mmap(NULL, num_bytes, PROT_READ, MAP_SHARED, fd, 0);
  atomic_printf("rpage:%p\n", rpage);
  test_assert(rpage != MAP_FAILED);

  // This tests both that the monitor gets activated again if the page is
  // remapped and that `write` works on a monitored page.
  lseek(fd, 0, SEEK_SET);
  magic = 0xb6b6b6b6;
  for (i = 0; i < num_bytes / sizeof(magic); ++i) {
    write(fd, &magic, sizeof(magic));
  }
  check_mapping(rpage, magic, num_bytes / sizeof(*rpage));

  atomic_puts("EXIT-SUCCESS");

  return 0;
}
