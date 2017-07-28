/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void check_mapping(int* rpage, int* wpage, ssize_t nr_ints) {
  int i;
  for (i = 0; i < nr_ints; ++i) {
    test_assert(wpage[i] == rpage[i]);

    wpage[i] = i;

    test_assert(rpage[i] == i && wpage[i] == rpage[i]);
  }
  atomic_printf("  %p and %p point at the same resource\n", rpage, wpage);
}

static void overwrite_file(const char* path, ssize_t num_bytes) {
  const int magic = 0x5a5a5a5a;
  int fd = open(path, O_TRUNC | O_RDWR, 0600);
  size_t i;
  for (i = 0; i < num_bytes / sizeof(magic); ++i) {
    write(fd, &magic, sizeof(magic));
  }
  close(fd);
}

int main(void) {
  size_t num_bytes = sysconf(_SC_PAGESIZE);
  static const char file_name[] = "temp";
  int fd = open(file_name, O_CREAT | O_EXCL | O_RDWR, 0600);
  int* wpage;
  int* rpage;
  int* old_wpage;

  test_assert(fd >= 0);

  overwrite_file(file_name, num_bytes - 4);

  unlink(file_name);

  wpage = mmap(NULL, num_bytes - 8, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  rpage = mmap(NULL, num_bytes, PROT_READ, MAP_SHARED, fd, 0);
  atomic_printf("wpage:%p\n", wpage);
  test_assert(wpage != (void*)-1 && rpage != (void*)-1 && rpage != wpage);

  old_wpage = wpage;

  /* Test a remapping that changes the number of pages */
  wpage = mremap(old_wpage, num_bytes - 8, num_bytes + 8, MREMAP_MAYMOVE);
  atomic_printf("remapped wpage:%p\n", wpage);
  test_assert(wpage != (void*)-1 && wpage != old_wpage);

  check_mapping(rpage, wpage, (num_bytes - 4) / sizeof(*wpage));

  atomic_puts("EXIT-SUCCESS");

  return 0;
}
