/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(int argc, char* argv[]) {
  long ncpus = sysconf(_SC_NPROCESSORS_ONLN);

  char arg[] = "--expected-cpus=";
  if (argc <= 1 || 0 != strncmp(argv[1], arg, sizeof(arg)-1)) {
    atomic_puts("Usage: sys_cpu_online --expected-cpus=[n] [--inner]");
    return 1;
  }

  // We test this both with and without the preload library
  // We also always allow 1 in case that's all the machine has
  test_assert(ncpus == atoi(argv[1]+sizeof(arg)-1) || ncpus == 1);

  if (argc > 2) {
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }

  // Test reading /sys/devices/system/cpu/online directly, making sure that
  // rr properly emulates the fd position
  int fd = open("/sys/devices/system/cpu/online", O_RDONLY);
  test_assert(fd >= 0);

  char result[1024];
  size_t nread = read(fd, &result, sizeof(result));
  test_assert(nread > 0);
  nread = read(fd, &result, sizeof(result));
  test_assert(nread == 0);
  close(fd);

  char* execv_argv[] = {"/proc/self/exe", argv[1], "--inner", NULL};
  // NULL here drops LD_PRELOAD
  execve("/proc/self/exe", execv_argv, NULL);
  test_assert(0 && "Should not have returned");
}
