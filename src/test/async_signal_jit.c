/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

typedef void (*jit_fn)(void*);

#if defined(__i386__)
#define ARCH_PC gregs[REG_EIP]
static const char code[] = {
  0x8b, 0x44, 0x24, 0x04,   // MOV EAX,[ESP+4]
  0x8a, 0x00,               // MOV AL,[EAX]
  0xc3                      // RET
};
#elif defined(__x86_64__)
#define ARCH_PC gregs[REG_RIP]
static const char code[] = {
  0x8a, 0x07,   // MOV AL,[RDI]
  0xc3          // RET
};
#else
#define ARCH_PC pc
static const char code[] = {
  0x0, 0x0, 0x40, 0xF9,   // LDR X0,[X0]
  0xC0, 0x03, 0x5F, 0xD6  // RET
};
#endif

static void* code_page;

static void on_bus(int sig, __attribute__((unused)) siginfo_t* si,
    __attribute__((unused)) void* ctx) {
  if (sig == SIGBUS && memcmp(code, code_page, sizeof(code)) == 0) {
    atomic_puts("EXIT-SUCCESS");
    _exit(0);
  } else {
    const char msg[] = "replay saw invalid instruction\n";
    write(STDERR_FILENO, msg, sizeof(msg) - 1);
    _exit(1);
  }
}

int main(void) {
  code_page = mmap(NULL, sizeof(code), PROT_READ | PROT_WRITE | PROT_EXEC,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  test_assert(code_page != MAP_FAILED);

  int fd = open("tmp", O_RDWR | O_CREAT, 0700);
  test_assert(fd >= 0);
  unlink("tmp");
  uint8_t* sigbus_page = mmap(NULL, 8, PROT_READ, MAP_PRIVATE, fd, 0);
  test_assert(sigbus_page != MAP_FAILED);

  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_sigaction = on_bus;
  sa.sa_flags = SA_SIGINFO;
  sigemptyset(&sa.sa_mask);
  test_assert(sigaction(SIGBUS, &sa, NULL) == 0);

  /* Patch the JIT page after those syscalls, then execute it. */
  memcpy(code_page, code, sizeof(code));
  __builtin___clear_cache((char*)code_page, (char*)(code_page + sizeof(code)));

  jit_fn fn = (jit_fn)code_page;
  fn(sigbus_page);

  atomic_puts("Should have exited, but didn't");
  return 1;
}
