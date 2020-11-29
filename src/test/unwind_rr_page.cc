/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* The C++ standard mandates an unwinder, so we assume that by making a C++
   file, the compiler will link in an appropriate unwind library */

extern "C" void *_Unwind_FindEnclosingFunction(void *);

void catcher(__attribute__((unused)) int signum,
             __attribute__((unused)) siginfo_t* siginfo_ptr,
             void* ucontext_ptr) {
    ucontext_t* ctx = (ucontext_t*)ucontext_ptr;
    uintptr_t ip;
#ifdef __i386__
    ip = ctx->uc_mcontext.gregs[REG_EIP];
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
