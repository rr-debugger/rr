#include "util.h"

#include <assert.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>

int main(__attribute__((unused)) int argc, char* argv[], char* argenv[]) {
  size_t page_size = sysconf(_SC_PAGESIZE);
  char last = 0;
  char* p;
  int proc_num = argv[2][0] - '0';
  int timeout = 30000; // 30 seconds

  if (argv[3][0] > '0') {
    if (fork() == 0) {
      char proc_num_arg[2] = {'0' + proc_num + 1, '\0'};
      char proc_to_start_arg[2] = {argv[3][0] - 1, '\0'};
      char* execv_argv[] = {argv[0], argv[1], proc_num_arg, proc_to_start_arg, NULL};
      execve("/proc/self/exe", execv_argv, argenv);
    }
  }

  int fd = open(argv[1], O_RDWR|O_CREAT, 0600);
  test_assert(fd >= 0);
  ftruncate(fd, page_size);
  p = (char*)mmap(0, page_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
  assert(p != MAP_FAILED);

  while (1) {
    if ((*p % 2) == proc_num) {
      if ((*p)++ >= 6) {
        atomic_printf("%d %d exiting.\n", getpid(), proc_num);
        usleep(50000); /* first recorded process exiting kills all others, wait a little. */
        return 0;
      }
    }
    if (last != *p)
      atomic_printf("%d\n", last = *p);
    usleep(50000);
    timeout -= 50;
    if (timeout < 0) {
        atomic_printf("timeout reached.\n");
        return 0;
    }
  }
  return 0;
}
