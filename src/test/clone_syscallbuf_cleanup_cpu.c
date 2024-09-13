/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static const size_t SHARED_MEMFD_SIZE = 4096;
static int shared_memfd;
static volatile char *shared_memfd_mapping;
static const char *CHILD_PROCESS_NAME = "clone_syscallbuf_cleanup_child";

void assert_syscallbuf_count(int expected) {
  FILE *f = fopen("/proc/self/maps", "r");
  test_assert(!!f);

  int actual = 0;
  for (;;) {
      size_t len = 0;
      char *line = NULL;
      int ret = getline(&line, &len, f);
      if (ret == -1) {
        break;
      }
      if (strstr(line, "rr-shared-syscallbuf")) {
        actual++;
      }
      free(line);
  }
  test_assert(expected == actual);
}

static int exec_proc(__attribute__((unused)) void* arg) {
  assert_syscallbuf_count(2);

  char memfd_name[PATH_MAX];
  snprintf(memfd_name, sizeof(memfd_name), "/proc/self/fd/%d", shared_memfd);
  execl("/proc/self/exe", CHILD_PROCESS_NAME, memfd_name, NULL);

  test_assert("Not reached" && 0);
  return 0;
}

static void execd_child_proc(char *shared_memfd_mapping_path) {
  // Need to re-map the shared memory we're going to use to poke the parent process
  shared_memfd = open(shared_memfd_mapping_path, O_RDWR);
  test_assert(shared_memfd != -1);
  shared_memfd_mapping = mmap(NULL, SHARED_MEMFD_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED,
                              shared_memfd, 0);
  test_assert(shared_memfd_mapping != MAP_FAILED);

  // And do said poking
  shared_memfd_mapping[0] = 1;
}


int main(int argc, char **argv) {
  // This is what get exec'd from exec_proc
  if (argc == 2 && strcmp(argv[0], CHILD_PROCESS_NAME) == 0) {
    execd_child_proc(argv[1]);
    return 0;
  }

  int ret;

  // Before forking, there should only be one syscallbuf
  assert_syscallbuf_count(1);

  // mmap some memory that can be shared across execve(2)
  shared_memfd = memfd_create("shared_page", 0);
  test_assert(shared_memfd != -1);
  ret = ftruncate(shared_memfd, SHARED_MEMFD_SIZE);
  test_assert(ret != -1);
  shared_memfd_mapping = mmap(NULL, SHARED_MEMFD_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED,
                              shared_memfd, 0);
  test_assert(shared_memfd_mapping != MAP_FAILED);
  shared_memfd_mapping[0] = 0;

  // Spawn a process which shares our address space, and will execve(2)
  const size_t stack_size = 1 << 20;
  void* exec_proc_stack = mmap(NULL, stack_size, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  test_assert(exec_proc_stack != MAP_FAILED);
  pid_t exec_proc_pid = clone(exec_proc, exec_proc_stack + stack_size, CLONE_VM | SIGCHLD,
                              NULL, NULL, NULL, NULL);
  test_assert(exec_proc_pid != -1);

  // Now spin waiting for the exec'd process to set a bit in the shard mapping
  while (shared_memfd_mapping[0] != 1) { ; }

  // This means the child exec'd so we should have cleaned up the syscallbuf
  assert_syscallbuf_count(1);

  // Reap the exec'd child
  test_assert(exec_proc_pid == waitpid(exec_proc_pid, NULL, 0));
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
