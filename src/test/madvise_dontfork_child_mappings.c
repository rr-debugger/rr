/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

#define MAX_RANGES 1024
#define MAX_HOLES 64

struct range {
  uint64_t start;
  uint64_t end;
};

static struct range parent_ranges[MAX_RANGES];
static int num_parent_ranges;
static char* holes[MAX_HOLES];

static void read_maps(uint64_t env, maps_callback callback) {
  FILE* maps = fopen("/proc/self/maps", "r");
  test_assert(maps != NULL);
  iterate_maps(env, callback, maps);
  test_assert(0 == fclose(maps));
}

static void add_parent_range(__attribute__((unused)) uint64_t env,
                             __attribute__((unused)) char* name,
                             map_properties_t* props) {
  test_assert(num_parent_ranges < MAX_RANGES);
  parent_ranges[num_parent_ranges].start = props->start;
  parent_ranges[num_parent_ranges].end = props->end;
  ++num_parent_ranges;
}

/* Writes the range to the pipe `env` unless it overlaps a range the parent
   had mapped. */
static void send_new_range(uint64_t env, __attribute__((unused)) char* name,
                           map_properties_t* props) {
  struct range r = { props->start, props->end };
  int i;
  for (i = 0; i < num_parent_ranges; ++i) {
    if (parent_ranges[i].start < r.end && r.start < parent_ranges[i].end) {
      return;
    }
  }
  test_assert((ssize_t)sizeof(r) == write((int)env, &r, sizeof(r)));
}

int main(void) {
  size_t page_size = sysconf(_SC_PAGESIZE);
  int fds[2];
  struct range r;
  ssize_t ret;
  int num_holes = 0;
  int i;
  pid_t child;
  int status;

  test_assert(0 == pipe(fds));
  read_maps(0, add_parent_range);

  /* Find the ranges that are mapped in a forked child but not here (under
     rr, memory that rr maps for the child). */
  child = fork();
  test_assert(child >= 0);
  if (!child) {
    read_maps(fds[1], send_new_range);
    _exit(0);
  }
  test_assert(0 == close(fds[1]));

  /* Map the last page of each such range and mark it MADV_DONTFORK. A
     child forked now starts with the address space layout the first child
     had, so these pages are unmapped in it. */
  while ((ret = read(fds[0], &r, sizeof(r))) > 0) {
    char* hole = (char*)(uintptr_t)(r.end - page_size);
    test_assert(ret == (ssize_t)sizeof(r));
    test_assert(num_holes < MAX_HOLES);
    test_assert(hole == mmap(hole, page_size, PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
                             -1, 0));
    test_assert(0 == madvise(hole, page_size, MADV_DONTFORK));
    holes[num_holes++] = hole;
  }
  test_assert(ret == 0);
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);

  child = fork();
  test_assert(child >= 0);
  if (!child) {
    for (i = 0; i < num_holes; ++i) {
      test_assert(-1 == madvise(holes[i], page_size, MADV_NORMAL));
      test_assert(ENOMEM == errno);
    }
    _exit(77);
  }
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);

  atomic_printf("%d DONTFORK holes checked\n", num_holes);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
