/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

static char parent_maps[65536];
static char child_maps[65536];

static void read_maps(char* buf, size_t size) {
  int fd = open("/proc/self/maps", O_RDONLY);
  size_t len = 0;
  ssize_t ret;
  test_assert(fd >= 0);
  while ((ret = read(fd, buf + len, size - 1 - len)) > 0) {
    len += ret;
  }
  test_assert(ret == 0);
  buf[len] = 0;
  close(fd);
}

static int overlaps_any(const char* maps, unsigned long start,
                        unsigned long end) {
  const char* line = maps;
  while (*line) {
    unsigned long s, e;
    const char* eol = strchr(line, '\n');
    if (sscanf(line, "%lx-%lx", &s, &e) == 2 && s < end && start < e) {
      return 1;
    }
    if (!eol) {
      break;
    }
    line = eol + 1;
  }
  return 0;
}

int main(int argc, char** argv) {
  pid_t child;
  int status;
  const char* line;
  void* p;

  if (argc > 1) {
    return 77;
  }

  read_maps(parent_maps, sizeof(parent_maps));

  if (0 == (child = vfork())) {
    char* const args[] = { argv[0], "child", NULL };
    /* Under rr, our scratch buffer is now mapped in the shared address space */
    read_maps(child_maps, sizeof(child_maps));
    execve(argv[0], args, environ);
    _exit(1);
  }

  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);

  /* Any mapping created by the child (e.g. rr's scratch buffer) should
     have been unmapped after the exec, so mapping over it should succeed.
     (Kernels without MAP_FIXED_NOREPLACE treat the address as a hint, which
     also succeeds when the region is free.) */
  line = child_maps;
  while (*line) {
    unsigned long start, end;
    const char* eol = strchr(line, '\n');
    if (sscanf(line, "%lx-%lx", &start, &end) == 2 &&
        !overlaps_any(parent_maps, start, end)) {
      p = mmap((void*)start, end - start, PROT_NONE,
               MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
      test_assert(p == (void*)start);
    }
    if (!eol) {
      break;
    }
    line = eol + 1;
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
