/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static volatile int stop;

static void handler(__attribute__((unused)) int sig) {}

static void term_handler(__attribute__((unused)) int sig) { stop = 1; }

#define STATEMENT(i)                                                           \
  if (a * (i) < b) {                                                           \
    ++a;                                                                       \
  } else {                                                                     \
    ++b;                                                                       \
  }
#define STATEMENT2(i) STATEMENT(i) STATEMENT(i + 1)
#define STATEMENT4(i) STATEMENT2(i) STATEMENT2(i + 2)
#define STATEMENT8(i) STATEMENT4(i) STATEMENT4(i + 4)
#define STATEMENT16(i) STATEMENT8(i) STATEMENT8(i + 8)
#define STATEMENT32(i) STATEMENT16(i) STATEMENT16(i + 16)
#define STATEMENT64(i) STATEMENT32(i) STATEMENT32(i + 32)
#define STATEMENT128(i) STATEMENT64(i) STATEMENT64(i + 64)
#define STATEMENT256(i) STATEMENT128(i) STATEMENT128(i + 128)
#define STATEMENT512(i) STATEMENT256(i) STATEMENT256(i + 256)
#define STATEMENT1024(i) STATEMENT512(i) STATEMENT512(i + 512)
#define STATEMENT2048(i) STATEMENT1024(i) STATEMENT1024(i + 1024)
#define STATEMENT4096(i) STATEMENT2048(i) STATEMENT2048(i + 2048)

static volatile int a;
static volatile int b;
static volatile int i;

int main(void) {
  test_assert(0 == signal(SIGUSR1, handler));
  test_assert(0 == signal(SIGUSR2, handler));
  test_assert(0 == signal(SIGTERM, term_handler));

  atomic_puts("ready");

  while (!stop) {
    STATEMENT4096(i);
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
