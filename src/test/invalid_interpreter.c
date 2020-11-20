/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

size_t page_size;

static void breakpoint(void) {
  int break_here = 1;
  (void)break_here;
}

void callback(__attribute__((unused)) uint64_t env, char* name, map_properties_t* props) {
  if (strstr(name, "/ld-") != 0) {
    test_assert(0 == munmap((void*)(uintptr_t)props->start, page_size));
    void* p = (void*)mmap((void*)(uintptr_t)props->start, page_size, PROT_NONE, MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
    test_assert(p != MAP_FAILED);
  }
}

int main(void) {
  page_size = sysconf(_SC_PAGESIZE);
  FILE* maps_file = fopen("/proc/self/maps", "r");
  iterate_maps(0, callback, maps_file);
  breakpoint();
  return 0;
}
