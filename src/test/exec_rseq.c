/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* The kernel drops rseq registrations at exec. Check that after an exec,
   nothing writes to where the rseq area registered before it was.

   We disable ASLR and exec ourselves, so the image after the exec is laid out
   exactly like the one before it, and `rs` is at the same address in both. */

static const uint32_t RSEQ_SIG = 0x12345678;
static const uint32_t CPU_INVALID = 10000000;

/* In .data, so a freshly exec'd image starts with these values. */
static struct rseq rs __attribute__((aligned(32))) = {
  .cpu_id_start = CPU_INVALID,
  .cpu_id = CPU_INVALID,
};

static void reexec(const char* stage, char** envp) {
  char* argv[] = { "/proc/self/exe", (char*)stage, NULL };
  execve("/proc/self/exe", argv, envp);
  test_assert(0 && "Failed exec!");
}

static void register_rseq(void) {
  int ret = syscall(RR_rseq, &rs, sizeof(rs), 0, RSEQ_SIG);
  if (ret == -1 && errno == ENOSYS) {
    atomic_puts("rseq not supported; ignoring test");
    atomic_puts("EXIT-SUCCESS");
    exit(0);
  }
  test_assert(ret == 0);
  test_assert(rs.cpu_id_start < CPU_INVALID);
  test_assert(rs.cpu_id < CPU_INVALID);
}

static void check_rseq_area_untouched(void) {
  test_assert(rs.cpu_id_start == CPU_INVALID);
  test_assert(rs.cpu_id == CPU_INVALID);
}

/* Run fn in a thread that doesn't have glibc's rseq registration. */
static void start_raw_thread(int (*fn)(void*)) {
  const size_t stack_size = 1 << 20;
  void* stack = mmap(NULL, stack_size, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  test_assert(stack != MAP_FAILED);
  test_assert(clone(fn, stack + stack_size,
                    CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_THREAD |
                        CLONE_SIGHAND,
                    NULL, NULL, NULL, NULL) > 0);
}

static int exec_from_thread(__attribute__((unused)) void* arg) {
  register_rseq();
  /* The thread-group leader exits and this thread takes over its tid. */
  reexec("check_thread", environ);
  return 0;
}

static int wait_forever(__attribute__((unused)) void* arg) {
  while (1) {
    pause();
  }
  return 0;
}

int main(int argc, char** argv) {
  if (argc == 1) {
    test_assert(syscall(RR_personality, ADDR_NO_RANDOMIZE) != -1);
    reexec("thread", environ);
  }

  if (!strcmp(argv[1], "thread")) {
    start_raw_thread(exec_from_thread);
    wait_forever(NULL);
  }

  if (!strcmp(argv[1], "check_thread")) {
    size_t n = 0;
    char** envp;
    check_rseq_area_untouched();
    /* Now exec from the thread-group leader while another thread exists.
       Keep glibc from registering rseq for the main thread so we can. */
    while (environ[n]) {
      ++n;
    }
    envp = calloc(n + 2, sizeof(char*));
    test_assert(envp != NULL);
    envp[0] = "GLIBC_TUNABLES=glibc.pthread.rseq=0";
    memcpy(envp + 1, environ, n * sizeof(char*));
    reexec("leader", envp);
  }

  if (!strcmp(argv[1], "leader")) {
    register_rseq();
    start_raw_thread(wait_forever);
    reexec("check_leader", environ);
  }

  test_assert(!strcmp(argv[1], "check_leader"));
  check_rseq_area_untouched();
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
