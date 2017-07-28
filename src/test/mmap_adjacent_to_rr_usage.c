/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#define RR_PAGE_ADDR 0x70000000

static void* map_addr;
static uintptr_t page_size;

/* Look for a mapping that looks like Monkeypatcher's stubs page,
   and try allocating our own page next to it to see if that causes
   problems for rr. */
void callback(__attribute__((unused)) uint64_t env,
              __attribute__((unused)) char* name, map_properties_t* props) {
  if (!strcmp(props->flags, "r-xp") &&
      (props->end - props->start) == page_size && props->start != 0x70000000 &&
      (int64_t)props->start >= 0) {
    map_addr = (void*)(uintptr_t)props->start;
  }
}

int main(void) {
  FILE* maps_file = fopen("/proc/self/maps", "r");
  void* ret;

  page_size = sysconf(_SC_PAGESIZE);
  iterate_maps(0, callback, maps_file);
  atomic_printf("Targeted map addr is %p\n", map_addr);
  ret = mmap(map_addr + page_size, page_size, PROT_READ | PROT_EXEC,
             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (ret == MAP_FAILED) {
    /* The allocation might not work because there might already
       be something there. If so, fail gracefully. */
    test_assert(errno == EINVAL);
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
