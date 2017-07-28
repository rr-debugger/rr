/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static int create_segment(size_t num_bytes) {
  char filename[] = "/dev/shm/rr-test-XXXXXX";
  int fd = mkstemp(filename);
  unlink(filename);
  test_assert(fd >= 0);
  ftruncate(fd, num_bytes);
  return fd;
}

struct mmap_arg_struct {
  unsigned long addr;
  unsigned long len;
  unsigned long prot;
  unsigned long flags;
  unsigned long fd;
  unsigned long offset;
};

static void run_test(void) {
  size_t num_bytes = sysconf(_SC_PAGESIZE);
  int fd = create_segment(num_bytes);
  int* wpage = mmap(NULL, num_bytes, PROT_WRITE, MAP_SHARED, fd, 0);
  size_t i;
  int* rpage;

  close(128);
  munmap(NULL, 0);

#if defined(__i386__)
  struct mmap_arg_struct args;
  args.addr = 0;
  args.len = num_bytes;
  args.prot = PROT_READ;
  args.flags = MAP_SHARED;
  args.fd = fd;
  args.offset = 0;
  rpage = (int*)syscall(SYS_mmap, &args, -1, -1, -1, -1, -1);
#elif defined(__x86_64__)
  rpage = (int*)syscall(SYS_mmap, 0, num_bytes, PROT_READ, MAP_SHARED, fd,
                        (off_t)0);
#else
#error unknown architecture
#endif

  test_assert(wpage != (void*)-1 && rpage != (void*)-1 && rpage != wpage);

  close(128);

  for (i = 0; i < num_bytes / sizeof(int); ++i) {
    wpage[i] = i;
    test_assert(rpage[i] == (ssize_t)i);
  }
}

int main(void) {
  pid_t c;
  int status;

  atomic_printf("%d: checking shared maps ...\n", getpid());
  run_test();

  if (0 == (c = fork())) {
    atomic_printf("%d:   and in fork child ...\n", getpid());
    run_test();
    exit(0);
  }
  test_assert(c == waitpid(c, &status, 0) && WIFEXITED(status) &&
              0 == WEXITSTATUS(status));

  atomic_puts("EXIT-SUCCESS");

  return 0;
}
