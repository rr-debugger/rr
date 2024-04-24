/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#define FILL_REGION_SIZE 2ULL*1024ULL*1024ULL*1024ULL // 2 GiB
#define PROBE_REGION_SIZE 200*1024ULL*1024ULL // 200 MiB

int main(__attribute__((unused)) int argc, __attribute__((unused)) char** argv) {
    FILE *f = fopen("/proc/sys/vm/max_map_count", "r");
    test_assert(f != NULL);

    size_t max_map_count;
    int ret = fscanf(f, "%zu", &max_map_count);
    test_assert(ret == 1);

    if (max_map_count > 100000) {
        atomic_puts("Skipping test: max_map_count is too high - test would take too long");
        atomic_puts("EXIT-SUCCESS");
        return 77;
    }

    // Prepare the fill region - we will fill this with a number of mappings close to the
    // maximum. We allow about a 256 mapping gap for rr's and the executable's mappings.
    size_t page_size = sysconf(_SC_PAGESIZE);
    size_t target_fill_mappings = max_map_count - 256;
    size_t fill_region_size = page_size * target_fill_mappings;
    char *fill_map = mmap(NULL, fill_region_size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    test_assert(fill_map != MAP_FAILED);
    for (size_t off = 0; off < fill_region_size; off += 2*page_size) {
        // Fracture the fill region into individual page-sized mappings.
        char *page = fill_map + off;
        test_assert(mprotect(page, page_size, PROT_READ) == 0);
    }

    // Now allocate the probe region
    char *probe_map = mmap(NULL, PROBE_REGION_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    test_assert(probe_map != MAP_FAILED);
    ret = madvise(probe_map, PROBE_REGION_SIZE, MADV_HUGEPAGE);
    if (ret == -1 && errno == EINVAL) {
        atomic_puts("Skipping test: CONFIG_TRANSPARENT_HUGEPAGE is disabled");
        atomic_puts("EXIT-SUCCESS");
        return 77;
    }
    test_assert(ret == 0);
    ret = madvise(probe_map, PROBE_REGION_SIZE, MADV_DONTDUMP);
    test_assert(ret == 0);

    // Now go through and re-map this mapping one page at a time, re-applying
    // the flags as we go. If rr is inconsistent about applying the flags
    // during replay, we will exceed the limit on the total number of mappings
    // and crash during replay.
    for (size_t off = 0; off < PROBE_REGION_SIZE; off += page_size) {
        char *map_target = probe_map + off;
        char *new_map = mmap(map_target, page_size,
            PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE | MAP_FIXED, -1, 0);
        test_assert(map_target == new_map);
        ret = madvise(new_map, page_size, MADV_HUGEPAGE);
        test_assert(ret == 0);
        if (off % (2*page_size) == 0) {
            ret = madvise(new_map, page_size, MADV_DONTDUMP);
            test_assert(ret == 0);
        } else {
            // Simulate a full syscallbuf - perform an unbuffered syscall
            ret = unbufferable_syscall(SYS_madvise, (uintptr_t)map_target,
                page_size, MADV_DONTDUMP);
            test_assert(ret == 0);
        }
    }
    atomic_puts("EXIT-SUCCESS");
    return 0;
}
