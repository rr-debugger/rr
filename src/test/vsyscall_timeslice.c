/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"
#include "util_internal.h"

#ifdef __x86_64__
void __attribute__((naked)) generate_tick(long generate) {
  __asm__ __volatile("test %%rdi, %%rdi\n\t"
  "jnz 1f\n\t"
  "ud2\n\t"
  "1: retq\n\t" :: "D"(generate));
  (void)generate;
}

static void test_vsyscall_timeslice_sig(void)
{
  intptr_t ret;
  uintptr_t syscall = SYS_rrcall_arm_time_slice;
  uintptr_t request = 1;
  register long r10 __asm__("r10") = 0;
  register long r8 __asm__("r8") = 0;
  register long r9 __asm__("r9") = 0;
  __asm__ __volatile(
    "syscall\n\t"
    "test %%rax, %%rax\n\t"
    "jnz .Ldone\n\t"
    // Create a pipeline stall - the CPU will speculate through
    // these, but because of the dependency from %rax (the result of the
    // division) to the %rdi argument of generate_tick will not be able to
    // retire the conditional branches therein, thus skidding our time
    // slice signal into the vsyscall.
    "movq $1, %%rax\n\t"
    "div %%rdi\n\t"
    "div %%rdi\n\t"
    "div %%rdi\n\t"
    "div %%rdi\n\t"
    "div %%rdi\n\t"
    "div %%rdi\n\t"
    "div %%rdi\n\t"
    "div %%rdi\n\t"
    // Two taken conditional branches here will trigger the
    // time slice expiration. We expect this to skid into
    // the subsequent vsyscall, triggering the condition we
    // want to test
    "movq %%rax, %%rdi\n\t"
    // N.B.: This only works if the branches contained herein are
    // predicted taken. Below we train the branch predictor to make
    // sure this happens.
    "callq generate_tick\n\t"
    "callq generate_tick\n\t"
    "xorq %%rdi, %%rdi\n\t"
    "movq $0xffffffffff600400, %%rax\n\t" // time(NULL)
    "callq *%%rax\n\t"
    ".Ldone:"
    "nop\n\t"
        : "=a"(ret)
        : "a"(syscall), "D"(request), "S"(NULL), "d"(NULL),
            "r"(r10), "r"(r8), "r"(r9)  : "cc", "memory");
  test_assert(ret > 0);
}

void callback(uint64_t env, char *name, __attribute__((unused)) map_properties_t* props) {
  if (strcmp(name, "[vsyscall]") == 0) {
    int* has_vsyscall = (int*)(uintptr_t)env;
    *has_vsyscall = 1;
  }
}
#endif

int main(void) {
  // x86_64 only
#ifdef __x86_64__
  FILE* maps_file = fopen("/proc/self/maps", "r");
  int has_vsyscall = 0;
  iterate_maps((uintptr_t)&has_vsyscall, callback, maps_file);

  if (!running_under_rr()) {
    atomic_puts("WARNING: This test only works under rr.");
  } else if (has_vsyscall) {
    for (int i = 0; i < 20000; ++i) {
      // Train the branch predictor that these branches are taken
      generate_tick(1);
    }
    test_vsyscall_timeslice_sig();
  }
#endif
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
