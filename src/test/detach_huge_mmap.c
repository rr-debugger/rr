/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util_internal.h"

static const int magic = 0xab;
static uint64_t size = 0x400000; /* 4 MB, at least the value in Task::dup_from */
static size_t page_size;
static void* pages[10];
static unsigned int idx; /*next index of pages*/

void test_alloc(char* mem, unsigned int count, off_t offset) {

  test_assert(0 == munmap(mem + size, page_size));

  /* one page near the start */
  test_assert(idx < sizeof(pages)/sizeof(pages[0]));
  pages[idx] = mem + page_size;
  memset(pages[idx], magic, page_size);
  idx++;

  /* one or more pages near or at the end */
  for (unsigned int i = 0; i < count; i++) {
    test_assert(idx < sizeof(pages)/sizeof(pages[0]));
    pages[idx] = mem + offset + i * page_size;
    memset(pages[idx], magic, page_size);
    idx++;
  }
}

int main(void) {
  page_size = sysconf(_SC_PAGESIZE);

  /* Create one big mapping, then break it up by munmap
   * into smaller ones, to better test the handling in
   * the end of mappings. */

  void* mem1 = mmap(NULL, 4 * (size + page_size), PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
  test_assert(mem1 != MAP_FAILED);

  void* mem2 = mem1 + size + page_size;
  void* mem3 = mem2 + size + page_size;
  void* mem4 = mem3 + size + page_size;

  test_alloc(mem1, 1, size - page_size);     /* one page used at last page */
  test_alloc(mem2, 1, size - page_size * 2); /* one page used before last page */
  test_alloc(mem3, 2, size - page_size * 2); /* two consecutive pages at last two pages */
  test_alloc(mem4, 2, size - page_size * 3); /* two consecutive pages before last page */

  pid_t pid = fork();
  if (pid == 0) {
    if (running_under_rr()) {
      rr_detach_teleport();
    }

    /* create one page for easier comparison */
    char* cmp = malloc(page_size * 3);
    test_assert(cmp != NULL);
    memset(cmp, magic, page_size * 3);

    /* check if the saved pages have the expected value */
    for (unsigned int i = 0; i < idx; i++) {
      test_assert(memcmp(pages[i], cmp, page_size) == 0);
    }

    return 0;
  }

  int status;
  wait(&status);
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
