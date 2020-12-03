/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* The C++ standard mandates an unwinder, so we assume that by making a C++
   file, the compiler will link in an appropriate unwind library */

extern "C" void *_Unwind_FindEnclosingFunction(void *);

#ifdef __i386__
void callback(uint64_t env, char* name, map_properties_t* props) {
  uintptr_t* ip = (uintptr_t*)env;
  if (strstr(name, "[vdso]") != 0) {
    if (*ip >= props->start && *ip < props->end) {
      /* This test does not work when built for i386 and using no syscall buffering.
         Because then ip is in [vdso] which seems not to be in the list of the dynamic loader. */
      atomic_puts("skipping. EXIT-SUCCESS");
      exit(0);
    }
  }
}
#endif

void catcher(__attribute__((unused)) int signum,
             __attribute__((unused)) siginfo_t* siginfo_ptr,
             void* ucontext_ptr) {
    ucontext_t* ctx = (ucontext_t*)ucontext_ptr;
    uintptr_t ip;
#ifdef __i386__
    ip = ctx->uc_mcontext.gregs[REG_EIP];
    FILE* maps_file = fopen("/proc/self/maps", "r");
    iterate_maps((uintptr_t)&ip, callback, maps_file);
#elif defined(__x86_64__)
    ip = ctx->uc_mcontext.gregs[REG_RIP];
#elif defined(__aarch64__)
    ip = ctx->uc_mcontext.pc;
#endif
    test_assert(_Unwind_FindEnclosingFunction((void*)ip) != NULL);
    atomic_puts("EXIT-SUCCESS");
    exit(0);
}

int main(void) {
    /* First make sure the unwind library itself is sane */
    test_assert(_Unwind_FindEnclosingFunction((char*)&main+1) == (void*)&main);

    struct sigaction sact;
    sigemptyset(&sact.sa_mask);
    sact.sa_flags = SA_SIGINFO;
    sact.sa_sigaction = catcher;
    sigaction(SIGALRM, &sact, NULL);

    /* Use syscall to ensure a patchable syscall location */
    struct timespec sleep = { 0, 0 };
    /* Give the syscallbuf a chance to patch this */
    test_assert(0 == syscall(SYS_clock_nanosleep, CLOCK_MONOTONIC, 0, &sleep, NULL));

    sleep.tv_sec = 1;

    alarm(1); /* timer will pop in 1 second */
    test_assert(0 == syscall(SYS_clock_nanosleep, CLOCK_MONOTONIC, 0, &sleep, NULL));
    return 0;
}
