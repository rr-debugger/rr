#include "util.h"

int main(int argc, char* argv[]) {
  sigset_t set;
  test_assert(argc == 1 || (argc == 2 && !strcmp("self", argv[1])));

  if (argc != 2) {
    char* argv[] = { "/proc/self/mem", "self", 0 };
    sigemptyset(&set);
    sigaddset(&set, SIGSEGV);
    sigprocmask(SIG_SETMASK, &set, NULL);
    execv("/proc/self/exe", argv);
    test_assert("Not reached" && 0);
  }

  sigprocmask(SIG_SETMASK, NULL, &set);
  test_assert(sigismember(&set, SIGSEGV));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
