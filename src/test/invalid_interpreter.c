/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

size_t page_size;

static void breakpoint(void) {
  int break_here = 1;
  (void)break_here;
}

#define N_MAX_TO_UNMAP 1024
static int n_to_unmap = 0;
static map_properties_t to_unmap[N_MAX_TO_UNMAP];

void callback(__attribute__((unused)) uint64_t env, char* name, map_properties_t* props) {
  if (strstr(name, "/ld-") != 0) {
    if (n_to_unmap >= N_MAX_TO_UNMAP)
      return;
    to_unmap[n_to_unmap++] = *props;
  }
}

int main(void) {
  page_size = sysconf(_SC_PAGESIZE);
  /* Trigger dl_runtime_resolve etc for mmap */
  mmap(NULL, page_size, PROT_NONE, MAP_ANONYMOUS, -1, 0);
  FILE* maps_file = fopen("/proc/self/maps", "r");
  iterate_maps(0, callback, maps_file);
  test_assert(n_to_unmap > 0);
  for (int i = 0; i < n_to_unmap; i++) {
    map_properties_t *props = &to_unmap[i];
    test_assert(0 == munmap((void*)(uintptr_t)props->start, page_size));
    void* p = (void*)mmap((void*)(uintptr_t)props->start, page_size, PROT_NONE, MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
    test_assert(p != MAP_FAILED);
  }
  breakpoint();
  return 0;
}
