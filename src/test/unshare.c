/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#define MAX_FDS 2048

extern int capset(cap_user_header_t header, const cap_user_data_t data);

static char tmp_name[] = "temp";
static uid_t uid;
static uid_t gid;

static void* start_thread(__attribute__((unused)) void* p) {
  test_assert(0 == unshare(CLONE_FILES));
  test_assert(0 == close(STDOUT_FILENO));
  return NULL;
}

static void test_mount(void) {
  test_assert(0 == mkdir("/aaa", 0777));
  /* Most filesystems can't be mounted in a non-root namespace,
     but proc can. */
  test_assert(0 == mount("dummy", "/aaa", "proc", 0, NULL));
  test_assert(0 == access("/aaa/cpuinfo", F_OK));
  test_assert(0 == umount("/aaa"));
  test_assert(0 == mount("dummy", "/aaa", "proc", 0, NULL));
  test_assert(0 == umount2("/aaa", 0));
  test_assert(0 == rmdir("/aaa"));
}

static void test_uids(void) {
  test_assert(0 == syscall(SYS_setreuid, 7, 7));
#ifdef SYS_setreuid32
  test_assert(0 == syscall(SYS_setreuid32, 7, 7));
#endif
  test_assert(0 == syscall(SYS_setregid, 8, 8));
#ifdef SYS_setreuid32
  test_assert(0 == syscall(SYS_setregid32, 8, 8));
#endif
  test_assert(0 == syscall(SYS_setresuid, 7, 7, 7));
#ifdef SYS_setresuid32
  test_assert(0 == syscall(SYS_setresuid32, 7, 7, 7));
#endif
  test_assert(0 == syscall(SYS_setresgid, 8, 8, 8));
#ifdef SYS_setresuid32
  test_assert(0 == syscall(SYS_setresgid32, 8, 8, 8));
#endif
  test_assert(0 == syscall(SYS_setuid, 7));
#ifdef SYS_setuid32
  test_assert(0 == syscall(SYS_setuid32, 7));
#endif
  test_assert(0 == syscall(SYS_setgid, 8));
#ifdef SYS_setgid32
  test_assert(0 == syscall(SYS_setgid32, 8));
#endif
  test_assert(7 == syscall(SYS_setfsuid, 7));
#ifdef SYS_setfsuid32
  test_assert(7 == syscall(SYS_setfsuid32, 7));
#endif
  test_assert(8 == syscall(SYS_setfsgid, 8));
#ifdef SYS_setfsgid32
  test_assert(8 == syscall(SYS_setfsgid32, 8));
#endif
  test_assert(7 == syscall(SYS_getuid));
#ifdef SYS_getuid32
  test_assert(7 == syscall(SYS_getuid32));
#endif
  test_assert(8 == syscall(SYS_getgid));
#ifdef SYS_getgid32
  test_assert(8 == syscall(SYS_getgid32));
#endif
  test_assert(7 == syscall(SYS_geteuid));
#ifdef SYS_geteuid32
  test_assert(7 == syscall(SYS_geteuid32));
#endif
  test_assert(8 == syscall(SYS_getegid));
#ifdef SYS_getegid32
  test_assert(8 == syscall(SYS_getegid32));
#endif
}

static void test_setns(void) {
  int uts_ns = open("/proc/self/ns/uts", O_RDONLY);
  pid_t child;
  int status;
  test_assert(uts_ns >= 0);

  child = fork();
  if (!child) {
    test_assert(0 == unshare(CLONE_NEWUTS));
    /* setns requires that this process be privileged in both the old and new
     * uts namespaces. We are. */
    test_assert(0 == setns(uts_ns, CLONE_NEWUTS));
    exit(76);
  }
  test_assert(child == wait(&status));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 76);
  test_assert(0 == close(uts_ns));
}

static void test_sethostname(void) {
  char name[] = "hello";
  char buf[1000];
  test_assert(0 == sethostname(name, strlen(name)));
  test_assert(0 == gethostname(buf, sizeof(buf)));
  test_assert(0 == strcmp(buf, name));
}

static void test_setdomainname(void) {
  char name[] = "kitty";
  char buf[1000];
  test_assert(0 == setdomainname(name, strlen(name)));
  test_assert(0 == getdomainname(buf, sizeof(buf)));
  test_assert(0 == strcmp(buf, name));
}

static void test_capset_and_drop_privileges(void) {
  struct __user_cap_header_struct hdr = { _LINUX_CAPABILITY_VERSION_1, 0 };
  struct __user_cap_data_struct data = { 0x1, 0x1, 0x1 };

  /* Test using capset. capset is privileged, but we are privileged
     in our user namespace. After this we are no longer privileged. */
  test_assert(0 == capset(&hdr, &data));
}

static void write_user_namespace_mappings(void) {
  char buf[100];
  int fd;

  fd = open("/proc/self/uid_map", O_WRONLY | O_CREAT);
  test_assert(fd >= 0);
  sprintf(buf, "7 %d 1\n", uid);
  test_assert((ssize_t)strlen(buf) == write(fd, buf, strlen(buf)));
  test_assert(0 == close(fd));

  /* Per user_namespaces(7), we need to write 'deny' to /proc/self/setgroups
   * before we set up gid_map. This means we can't test setgroups here. Oh well.
   */
  fd = open("/proc/self/setgroups", O_WRONLY | O_CREAT);
  /* This file does not exist in some old kernel */
  if (fd >= 0) {
    sprintf(buf, "deny");
    test_assert((ssize_t)strlen(buf) == write(fd, buf, strlen(buf)));
    test_assert(0 == close(fd));
  }

  fd = open("/proc/self/gid_map", O_WRONLY | O_CREAT);
  test_assert(fd >= 0);
  sprintf(buf, "8 %d 1\n", gid);
  test_assert((ssize_t)strlen(buf) == write(fd, buf, strlen(buf)));
  test_assert(0 == close(fd));
}

static void run_child(void) {
  pid_t child;
  int status;

  child = fork();
  if (!child) {
    test_assert(0 == mkdir("/proc", 0777));
    test_assert(0 == mount("dummy", "/proc", "proc", 0, NULL));

    write_user_namespace_mappings();

    /* Test creating a nested child */
    pid_t nested_child = fork();
    if (!nested_child) {
      exit(77);
    }
    test_assert(nested_child == wait(&status));
    test_assert(WIFEXITED(status) && 77 == WEXITSTATUS(status));

    /* Test creating a thread */
    pthread_t thread;
    pthread_create(&thread, NULL, start_thread, NULL);
    pthread_join(thread, NULL);

    test_mount();
    test_uids();
    test_setns();
    test_sethostname();
    test_setdomainname();

    test_assert(0 == umount("/proc"));
    test_assert(0 == rmdir("/proc"));

    test_capset_and_drop_privileges();

    /* stdout should still be writable due to the unshare() in start_thread */
    test_assert(13 == write(STDOUT_FILENO, "EXIT-SUCCESS\n", 13));
    exit(55);
  }
  test_assert(child == wait(&status));
  test_assert(WIFEXITED(status) && 55 == WEXITSTATUS(status));
}

static int run_test(void) {
  int ret;
  int fd;
  struct rlimit nofile;
  int fd_limit;

  test_assert(0 == getrlimit(RLIMIT_NOFILE, &nofile));
  if (nofile.rlim_cur == RLIM_INFINITY || nofile.rlim_cur > MAX_FDS) {
    fd_limit = MAX_FDS;
  } else {
    fd_limit = nofile.rlim_cur;
  }

  for (fd = STDERR_FILENO + 1; fd < fd_limit; ++fd) {
    ret = close(fd);
    test_assert(ret == 0 || (ret == -1 && errno == EBADF));
  }

  ret = unshare(CLONE_NEWUSER);
  if (ret == -1 && (errno == EINVAL || errno == EPERM)) {
    atomic_puts("EXIT-SUCCESS");
    return 77;
  }
  test_assert(0 == ret);

  test_assert(0 == unshare(CLONE_NEWNS));
  test_assert(0 == unshare(CLONE_NEWIPC));
  test_assert(0 == unshare(CLONE_NEWNET));
  test_assert(0 == unshare(CLONE_NEWUTS));
  ret = unshare(CLONE_NEWPID);
  if (ret == -1 && errno == EINVAL) {
    atomic_puts("EXIT-SUCCESS");
    return 77;
  }

  test_assert(0 == ret);

  test_assert(0 == chroot(tmp_name));

  run_child();
  return 77;
}

int main(void) {
  pid_t child;
  int ret;
  int status;

  uid = getuid();
  gid = getgid();

  test_assert(0 == mkdir(tmp_name, 0700));

  child = fork();
  if (!child) {
    return run_test();
  }
  ret = wait(&status);
  test_assert(0 == rmdir(tmp_name));
  test_assert(child == ret);
  test_assert(WIFEXITED(status) && 77 == WEXITSTATUS(status));

  return 0;
}
