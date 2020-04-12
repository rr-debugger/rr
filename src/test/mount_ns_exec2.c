/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "nsutils.h"
#include "util.h"

int main(int argc, char* argv[]) {
  if (argc > 1 && strcmp(argv[1], "in_copy") == 0) {
    // Try to do an mmap call, just to stress that code path
    int selffd = open("/proc/self/exe", O_RDONLY);
    test_assert(selffd != -1);
    void *addr = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, selffd, 4096);
    test_assert(addr != MAP_FAILED);
    check_data(addr, 4096);
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }

  if (-1 == try_setup_ns(CLONE_NEWNS)) {
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }

  char exe_buf[PATH_MAX+1];
  memset(exe_buf, 0, sizeof(exe_buf));
  ssize_t nread = readlink("/proc/self/exe", exe_buf, sizeof(exe_buf)-1);
  test_assert(nread != -1);

  char *exe_name = strrchr(exe_buf, '/');
  *exe_name = '\0';
  exe_name += 1;

  test_assert(0 == mkdir("mountpoint", 0700));

  int mountpoint_fd = open("mountpoint", O_PATH);
  test_assert(mountpoint_fd != -1);

  // Copy the exe to the mountpoint as well to make sure rr doesn't
  // accidentally pick up the wrong one to put in the trace
  struct stat buf;
  int ret = stat("/proc/self/exe", &buf);
  test_assert(ret != -1);
  int src_fd = open("/proc/self/exe", O_RDONLY);
  test_assert(src_fd != -1);
  int dst_fd = openat(mountpoint_fd, exe_name, O_WRONLY | O_CREAT, 0700);
  test_assert(dst_fd != -1);
  off_t offset = 0;
  // Only send the first 4096 bytes, so we really crash if somebody tries to
  // Use that file instead
  test_assert(sendfile(dst_fd, src_fd, &offset, 4096) == 4096);
  close(src_fd);
  fsync(dst_fd);
  close(dst_fd);
  close(mountpoint_fd);

  test_assert(0 == mount(exe_buf, "mountpoint", "none", MS_BIND, NULL));

  char exe_path[PATH_MAX];
  ssize_t n = snprintf(exe_path, sizeof(exe_path), "mountpoint/%s", exe_name);
  test_assert(n > 0 && n < (ssize_t)sizeof(exe_path));

  char* const new_argv[] = { exe_path, "in_copy", NULL };
  execve(exe_path, new_argv, environ);
  test_assert(0);
  return 1;
}
