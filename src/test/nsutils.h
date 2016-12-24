/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef NSUTILS_H
#define NSUTILS_H

#include "rrutil.h"

static int open_proc_file(pid_t pid, const char* file, int mode) {
  char path[100];
  ssize_t n = snprintf(path, sizeof(path), "/proc/%d/%s", pid, file);
  test_assert(n >= 0 && n < (ssize_t)sizeof(path));
  int fd = open(path, mode);
  test_assert(fd != -1);
  return fd;
}

static int try_setup_ns(int ns_kind) {
  int err = unshare(ns_kind);
  if (err == -1) {
    // Try again using user namespace functionality
    test_assert(errno == EPERM);

    int child_block[2], parent_block[2];
    pipe(child_block);
    pipe(parent_block);

    pid_t pid = getpid();
    if (fork() == 0) {
      close(child_block[1]);
      close(parent_block[0]);

      // This will block until the parent closes fds[1]
      test_assert(0 == read(child_block[0], NULL, 1));
      close(child_block[0]);

      // Deny setgroups
      int setgroups_fd = open_proc_file(pid, "setgroups", O_WRONLY);
      char deny[] = "deny";
      test_assert(write(setgroups_fd, deny, sizeof(deny)) == sizeof(deny));
      close(setgroups_fd);

      // Make us root
      ssize_t nbytes;
      int uidmap_fd = open_proc_file(pid, "uid_map", O_WRONLY);
      test_assert(uidmap_fd != -1);
      char uidmap[100];
      nbytes = snprintf(uidmap, (ssize_t)sizeof(uidmap), "0\t%d\t1", getuid());
      test_assert(nbytes > 0 && nbytes <= (ssize_t)sizeof(uidmap));
      test_assert(write(uidmap_fd, uidmap, nbytes) == nbytes);
      test_assert(uidmap_fd);

      int gidmap_fd = open_proc_file(pid, "gid_map", O_WRONLY);
      test_assert(gidmap_fd != -1);
      char gidmap[100];
      nbytes = snprintf(gidmap, (ssize_t)sizeof(gidmap), "0\t%d\t1", getgid());
      test_assert(nbytes > 0 && nbytes <= (ssize_t)sizeof(gidmap));
      test_assert(write(gidmap_fd, gidmap, nbytes) == nbytes);

      close(parent_block[1]);

      _exit(0);
    }
    close(child_block[0]);
    close(parent_block[1]);

    err = unshare(ns_kind | CLONE_NEWUSER);

    if (err == -1) {
      test_assert(errno == EPERM);
      atomic_printf("Skipping test because namespaces are\n"
                    "not available at this privilege level");
      return -1;
    }

    close(child_block[1]);
    // Wait until our child has made us root in this namespace;
    test_assert(0 == read(parent_block[0], NULL, 1));
    close(parent_block[0]);
  }

  return 0;
}

#endif // NSUTILS_H
