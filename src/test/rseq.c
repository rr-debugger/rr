/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

struct rseq {
  uint32_t cpu_id_start;
  uint32_t cpu_id;
  uint64_t rseq_cs;
  uint32_t flags;
} __attribute__((aligned(32)));

struct rseq_cs {
  uint32_t version;
  uint32_t flags;
  uint64_t start_ip;
  uint64_t post_commit_offset;
  uint64_t abort_ip;
} __attribute__((aligned(32)));

static struct rseq rs;
static struct rseq_cs rs_cs;

static const uint32_t RSEQ_SIG = 0x12345678;

extern char start_ip;
extern char end_ip;
extern char abort_ip;

static uint64_t aborts;
static uint64_t jump_aborts;

static volatile uint32_t dummy;

static void do_section(void) {
  int did_abort = 0;

  rs.rseq_cs = (uint64_t)(uintptr_t)&rs_cs;
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
#endif
  if (did_abort) {
    ++jump_aborts;
    test_assert(!rs.rseq_cs);
  }
  if (!rs.rseq_cs) {
    ++aborts;
  }
  rs.rseq_cs = 0;
}

static int main_child_thread(__attribute__((unused)) void* arg) {
  struct rseq rs;
  int ret = syscall(RR_rseq, &rs, sizeof(rs), 0, RSEQ_SIG);
  test_assert(ret == 0);
  return 0;
}

static int main_child(void) {
  int ret = syscall(RR_rseq, &rs, sizeof(rs), 0, RSEQ_SIG);
  int i;
  int status;
  pid_t child;

  if (ret == -1 && errno == ENOSYS) {
    atomic_puts("rseq not supported; ignoring test");
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }
  test_assert(ret == 0);
  test_assert(rs.cpu_id_start < 10000000);
  test_assert(rs.cpu_id < 10000000);

#if defined(__x86_64__) || defined(__i386__)
  rs_cs.start_ip = (uint64_t)(uintptr_t)&start_ip;
  rs_cs.post_commit_offset = (uint64_t)(uintptr_t)&end_ip - rs_cs.start_ip;
  rs_cs.abort_ip = (uint64_t)(uintptr_t)&abort_ip;
#endif

  const size_t stack_size = 1 << 20;
  void* stack = mmap(NULL, stack_size, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  test_assert(stack != MAP_FAILED);

  clone(main_child_thread, stack + stack_size,
        CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_THREAD | CLONE_SIGHAND,
        NULL, NULL, NULL, NULL);

  child = fork();
  if (!child) {
    for (i = 0; i < 300000000; ++i) {
      do_section();
    }

    atomic_printf("Detected %lld aborts, %lld jump aborts\n",
                  (long long)aborts, (long long)jump_aborts);
    return 77;
  }
  atomic_printf("child %d\n", child);
  for (i = 0; i < 1000; ++i) {
    sched_yield();
  }
  ret = waitpid(child, &status, 0);
  test_assert(ret == child);
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}

static int main_child_wrapper(__attribute__((unused)) void* arg) {
  exit(main_child());
}

int main(void) {
  const size_t stack_size = 1 << 20;
  void* stack = mmap(NULL, stack_size, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  test_assert(stack != MAP_FAILED);

  rs.cpu_id_start = 10000000;
  rs.cpu_id = 10000001;

  clone(main_child_wrapper, stack + stack_size,
        CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_THREAD | CLONE_SIGHAND,
        NULL, NULL, NULL, NULL);
  pause();
}