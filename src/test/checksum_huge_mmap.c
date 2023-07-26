/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#if defined(__aarch64__) || defined(__x86_64__)
#define HUGE_MMAP_SIZE 1ULL*1024ULL*1024ULL*1024ULL*1024ULL // 1 TiB
#else
#define HUGE_MMAP_SIZE 2ULL*1024ULL*1024ULL*1024ULL // 2 GiB
#endif

int main(__attribute__((unused)) int argc, __attribute__((unused)) char** argv) {
    pid_t pid = getpid();
    char *huge_map = mmap(NULL, HUGE_MMAP_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (!huge_map) {
        atomic_printf("The kernel refused our huge allocation. A ulimit over memory overcommit restriction may be in place. Skipping test.");
        atomic_puts("EXIT-SUCCESS");
        return 77;
    }

    atomic_printf("Info: %d %p\n", pid, huge_map);

    // Touch the first and the last page and print in between to make sure that a checksum happens.
    *(int*)huge_map = 1;
    *(int*)(huge_map + HUGE_MMAP_SIZE - 1024) = 1;
    atomic_puts("Test 1");

    // Reset to zero, but the page no longer is a paged-out, demand page.
    *(int*)huge_map = 0;
    *(int*)(huge_map + HUGE_MMAP_SIZE - 1024) = 0;
    atomic_puts("Test 2");

    atomic_puts("EXIT-SUCCESS");
    return 0;
}