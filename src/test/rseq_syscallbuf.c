/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static struct rseq* rs_ptr;
static struct rseq_cs rs_cs;

static const uint32_t RSEQ_SIG = 0x12345678;

// Use hidden symbols to make sure we refer to the assembly symbol
// rather than through GOT
__attribute__((visibility("hidden"))) extern char start_ip;
__attribute__((visibility("hidden"))) extern char end_ip;
__attribute__((visibility("hidden"))) extern char abort_ip;

static uint64_t aborts;
static uint64_t jump_aborts;

static volatile uint32_t dummy;

static void do_section(void) {
  int did_abort = 0;

  rs_ptr->rseq_cs = (uint64_t)(uintptr_t)&rs_cs;
#if defined(__x86_64__) || defined(__i386__)
  __asm__ __volatile__ (
    "start_ip:\n\t"
    "movl $1234,%0\n\t"
    "movl $1234,%0\n\t"
    "movl $1234,%0\n\t"
    "movl $1234,%0\n\t"
    "jmp 1f\n\t"
    "end_ip:\n\t"
    ".int 0x12345678\n\t"
    "abort_ip:\n\t"
    "movb $1,%1\n\t"
    "1:\n\t"
    : : "m"(dummy), "m"(did_abort));
#elif defined(__aarch64__)
  int dummy2;
  __asm__ __volatile__ (
    "start_ip:\n\t"
    "mov %1, 1234\n\t"
    "str %1, %2\n\t"
    "str %1, %2\n\t"
    "str %1, %2\n\t"
    "str %1, %2\n\t"
    "b 1f\n\t"
    "end_ip:\n\t"
    ".int 0x12345678\n\t"
    "abort_ip:\n\t"
    "mov %0, 1\n\t"
    "1:\n\t"
    : "+r"(did_abort), "=&r"(dummy2) : "m"(dummy));
#endif
  if (did_abort) {
    ++jump_aborts;
    test_assert(!rs_ptr->rseq_cs);
  }
  if (!rs_ptr->rseq_cs) {
    ++aborts;
  }
  rs_ptr->rseq_cs = 0;
}

static int passed_argc;
static char** passed_argv;
static char** passed_envp;

static int main_child(void) {
  int i;
  int status;
  pid_t child;
  int ret;
  volatile char* stop_flag = (char*)mmap(NULL, 1, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
  test_assert(stop_flag != MAP_FAILED);

  ret = syscall(RR_rseq, rs_ptr, sizeof(*rs_ptr), 0, RSEQ_SIG);
  if (ret == -1 && errno == ENOSYS) {
    atomic_puts("rseq not supported; ignoring test");
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }
  test_assert(ret == 0);
  test_assert(rs_ptr->cpu_id_start < 10000000);
  test_assert(rs_ptr->cpu_id < 10000000);

  rs_cs.start_ip = (uint64_t)(uintptr_t)&start_ip;
  rs_cs.post_commit_offset = (uint64_t)(uintptr_t)&end_ip - rs_cs.start_ip;
  rs_cs.abort_ip = (uint64_t)(uintptr_t)&abort_ip;

  child = fork();
  if (!child) {
    /* Issue invalid rseq call to make sure that doesn't break syscall buffering */
    ret = syscall(RR_rseq, rs_ptr, sizeof(*rs_ptr), 0xffffffff, RSEQ_SIG);
    test_assert(ret == -1);
    test_assert(errno == EINVAL);

    struct timeval tv;
    while (!*stop_flag) {
      gettimeofday(&tv, NULL);
      do_section();
    }

    atomic_printf("Detected %lld aborts, %lld jump aborts\n",
                  (long long)aborts, (long long)jump_aborts);
    return 77;
  }
  atomic_printf("child %d\n", child);
  /* Try to interrupt the child 50 times */
  for (i = 0; i < 50; ++i) {
    sched_yield();
  }
  *stop_flag = 1;
  ret = waitpid(child, &status, 0);
  test_assert(ret == child);
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}

static int main_child_wrapper(__attribute__((unused)) void* arg) {
  exit(main_child());
}

int main(int argc, char** argv, char** envp) {
  const size_t stack_size = 1 << 20;
  void* stack = mmap(NULL, stack_size, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  test_assert(stack != MAP_FAILED);

  passed_argc = argc;
  passed_argv = argv;
  passed_envp = envp;

  rs_ptr = (struct rseq*)mmap(NULL, sizeof(*rs_ptr), PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  test_assert(rs_ptr != MAP_FAILED);
  rs_ptr->cpu_id_start = 10000000;
  rs_ptr->cpu_id = 10000001;

  /* Do the real work in a thread that doesn't have glibc's rseq setup installed */
  clone(main_child_wrapper, stack + stack_size,
        CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_THREAD | CLONE_SIGHAND,
        NULL, NULL, NULL, NULL);
  pause();
}
