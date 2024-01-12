/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static int compare(const void* a, const void* b) {
  if (*(uint64_t*)a < *(uint64_t*)b) {
    return -1;
  }
  if (*(uint64_t*)a > *(uint64_t*)b) {
    return 1;
  }
  return 0;
}

static int addr_bits(void) {
#if defined(__i386__)
  return 32;
#elif defined(__x86_64__)
  return 47;
#elif defined(__aarch64__)
  return 48;
#else
#error Define your architecture here
#endif
}

int check_range_available(uint64_t* ptrs, size_t num_ptrs, uint64_t map_size, uint64_t range_size) {
  if (!num_ptrs) {
    return 1;
  }
  qsort(ptrs, num_ptrs, sizeof(uint64_t), compare);
  uint64_t last = 0;
  for (size_t i = 0; i < num_ptrs; ++i) {
    if (ptrs[i] - last >= range_size) {
      return 1;
    }
    last = ptrs[i] + map_size;
  }
  uint64_t addr_max = ((uint64_t)1) << addr_bits();
  if (addr_max - last >= range_size) {
    return 1;
  }

  FILE* maps_file = fopen("/proc/self/maps", "r");
  while (!feof(maps_file)) {
    char maps_line[1024];
    fgets(maps_line, sizeof(maps_line), maps_file);
    fputs(maps_line, stdout);
  }

  return 0;
}

int main(void) {
  int i;
  if (sizeof(void*) == 4) {
    for (i = 0; i < 10; ++i) {
      void* p = mmap(NULL, 512*1024*1024, PROT_NONE,
                     MAP_NORESERVE | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
      if (p == MAP_FAILED) {
        test_assert(errno == ENOMEM);
        break;
      }
    }
  } else {
    uint64_t ptrs[1024];
    uint64_t map_size = ((uint64_t)512)*1024*1024*1024;
    for (i = 0; i < 1024; ++i) {
      void* p = mmap(NULL, map_size, PROT_NONE,
                     MAP_NORESERVE | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
      if (p == MAP_FAILED) {
        test_assert(errno == ENOMEM);
        break;
      }
      ptrs[i] = (uintptr_t)p;
    }
    test_assert(check_range_available(ptrs, i, map_size,
                                      ((uint64_t)4)*1024*1024*1024*1024));
  }
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
