/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static int pipefds[2];
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
  // Close the reading end of the pipe in this process
  close(pipefds[0]);

  // Wait for the parent to be blocked in a read(2) syscall waiting on the pipe
  char wchan_path[PATH_MAX];
  snprintf(wchan_path, PATH_MAX, "/proc/%d/wchan", getppid());
  char wchan[1024] = {0};
  do {
    FILE *f = fopen(wchan_path, "r");
    size_t s = fread(wchan, 1, sizeof(wchan) - 1, f);
    fclose(f);
    wchan[s] = 0;
  } while (strstr(wchan, "pipe_read") == 0);

  sleep(1);

  assert_syscallbuf_count(2);
  // Now exec our child. The child will un-freeze the parent.
  char wpipe_name[PATH_MAX];
  snprintf(wpipe_name, sizeof(wpipe_name), "/proc/self/fd/%d", pipefds[1]);
  execl("/proc/self/exe", CHILD_PROCESS_NAME, wpipe_name, NULL);

  test_assert("Not reached" && 0);
  return 0;
}

static void execd_child_proc(char *pipe_file) {
  // Unblock the parent by writing a . to the shared pipe
  pipefds[1] = open(pipe_file, O_WRONLY);
  test_assert(pipefds[1] != -1);

  char dummy[1] = { '.' };
  int ret = write(pipefds[1], dummy, 1);
  test_assert(ret == 1);

  close(pipefds[1]);
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

  ret = pipe2(pipefds, 0);
  test_assert(ret != -1);

  // Spawn a process which shares our address space, and will execve(2)
  const size_t stack_size = 1 << 20;
  void* exec_proc_stack = mmap(NULL, stack_size, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  pid_t exec_proc_pid = clone(exec_proc, exec_proc_stack + stack_size, CLONE_VM | SIGCHLD,
                              NULL, NULL, NULL, NULL);

  // This proces needs the read end of the pipe, close the write end
  close(pipefds[1]);

  // Block ourselves attempting to read from the pipe.
  char dummy[1] = { 0 };
  ret = read(pipefds[0], dummy, 1);
  // When we are woken up, we should have read a byte
  test_assert(ret == 1);
  test_assert(dummy[0] == '.');

  // This means the child exec'd so we should have cleaned up the syscallbuf
  assert_syscallbuf_count(1);

  // Reap the exec'd child
  test_assert(exec_proc_pid == waitpid(exec_proc_pid, NULL, 0));
  atomic_puts("EXIT-SUCCESS");
  return 0;
}

