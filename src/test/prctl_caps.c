/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "nsutils.h"
#include "util.h"

#include <linux/securebits.h>

static void verify_caps(uint32_t caps) {
  struct __user_cap_header_struct* hdr;
  struct __user_cap_data_struct* data;
  hdr = malloc(sizeof(*hdr));
  hdr->version = _LINUX_CAPABILITY_VERSION_3;
  hdr->pid = 0;
  data = malloc(sizeof(*data) * 2);
  test_assert(0 == syscall(SYS_capget, hdr, data));
  test_assert(data[0].permitted == caps);
  test_assert(data[1].permitted == 0);
  free(hdr);
  free(data);
}

static void raise_in_inheritable_set(uint32_t caps) {
  struct __user_cap_header_struct* hdr;
  struct __user_cap_data_struct* data;
  hdr = malloc(sizeof(*hdr));
  hdr->version = _LINUX_CAPABILITY_VERSION_3;
  hdr->pid = 0;
  data = malloc(sizeof(*data) * 2);
  test_assert(0 == syscall(SYS_capget, hdr, data));
  data[0].inheritable |= caps;
  test_assert(0 == syscall(SYS_capset, hdr, data));
}

static void fork_exec_self(char* op) {
  pid_t child;
  int status;
  if ((child = fork()) == 0) {
    char* const argv[] = { "/proc/self/exe", op, NULL };
    execve("/proc/self/exe", argv, environ);
    _exit(1);
  }
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

int main(int argc, char* argv[]) {
  if (argc > 1) {
    if (strcmp(argv[1], "verify_only_admin") == 0) {
      verify_caps(((uint32_t)1) << CAP_SYS_ADMIN);
      return 0;
    } else if (strcmp(argv[1], "verify_no_caps") == 0) {
      verify_caps(0);
      return 0;
    } else {
      return 1;
    }
  }

  if (-1 == try_setup_ns_no_root(CLONE_NEWUSER)) {
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }

  test_assert(1 == prctl(PR_CAPBSET_READ, CAP_SYS_ADMIN));

  int err = prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0);
  if (err == -1) {
    // This is a rather new option, may not be available in all kernels
    // we want to run on
    test_assert(errno == EINVAL);
  } else {
    fork_exec_self("verify_no_caps");
    test_assert(
        0 == prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, CAP_SYS_ADMIN, 0, 0));
    raise_in_inheritable_set((uint32_t)1 << CAP_SYS_ADMIN);
    test_assert(
        0 == prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, CAP_SYS_ADMIN, 0, 0));
    test_assert(
        1 == prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, CAP_SYS_ADMIN, 0, 0));
    fork_exec_self("verify_only_admin");
    test_assert(
        0 == prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_LOWER, CAP_SYS_ADMIN, 0, 0));
    fork_exec_self("verify_no_caps");
  }

  test_assert(0 == prctl(PR_CAPBSET_DROP, CAP_SYS_ADMIN));
  test_assert(0 == prctl(PR_CAPBSET_READ, CAP_SYS_ADMIN));

  test_assert(0 == try_setup_ns(CLONE_NEWUSER));

  test_assert(1 == prctl(PR_CAPBSET_READ, CAP_SYS_ADMIN));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
