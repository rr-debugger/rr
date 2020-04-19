/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(int argc, char* argv[] __attribute__((unused))) {
  long ncpus = sysconf(_SC_NPROCESSORS_ONLN);

  // We test this both with and without the preload library
  test_assert(ncpus == 1);

  if (argc > 1) {
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

  char* execv_argv[] = {"/proc/self/exe", "--inner", NULL};
  // NULL here drops LD_PRELOAD
  execve("/proc/self/exe", execv_argv, NULL);
  test_assert(0 && "Should not have returned");
}
