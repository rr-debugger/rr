/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

#define PAGE_ZEROES (PAGE_SIZE / sizeof(int))

static size_t count_page_zeroes(int* p) {
  size_t zeroes = 0;
  size_t i;
  for (i = 0; i < PAGE_SIZE / sizeof(*p); ++i) {
    if (!p[i]) {
      ++zeroes;
    }
  }
  return zeroes;
}

static void set_page_values_nonzero(int* p) {
  size_t i;
  for (i = 0; i < PAGE_SIZE / sizeof(*p); ++i) {
    p[i] = i + 1;
  }
}

int main(void) {
  int* page;
  void* fixed_area;

  fixed_area =
      mmap(NULL, PAGE_SIZE * 5, PROT_NONE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  test_assert(fixed_area != MAP_FAILED);
  test_assert(0 == munmap(fixed_area, PAGE_SIZE * 5));

  page = mmap(fixed_area + PAGE_SIZE, PAGE_SIZE, PROT_READ | PROT_WRITE,
              MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  test_assert(page != MAP_FAILED);
  test_assert(count_page_zeroes(page) == PAGE_ZEROES);

  set_page_values_nonzero(page);
  test_assert(0 == madvise(page, PAGE_SIZE, MADV_DONTNEED));
  test_assert(count_page_zeroes(page) == PAGE_ZEROES);

  set_page_values_nonzero(page);
  test_assert(0 == madvise(page, 1, MADV_DONTNEED));
  test_assert(count_page_zeroes(page) == PAGE_ZEROES);

  set_page_values_nonzero(page);
  test_assert(-1 == madvise(fixed_area - 1, PAGE_SIZE * 5, MADV_DONTNEED));
  test_assert(EINVAL == errno);
  /* check this madvise had no effect */
  test_assert(count_page_zeroes(page) < PAGE_ZEROES);

  test_assert(-1 == madvise(fixed_area, PAGE_SIZE * 5, MADV_DONTNEED));
  test_assert(ENOMEM == errno);
  /* check this madvise did take effect */
  test_assert(count_page_zeroes(page) == PAGE_ZEROES);

  atomic_puts("EXIT-SUCCESS");

  return 0;
}
