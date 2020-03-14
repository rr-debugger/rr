/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void C(void) { atomic_puts("in C"); }

// In our test driver, we rely on the debugger stopping
// on the first call inside the function. However, different
// versions of gdb/gcc are inconsistent about whether the breakpoint
// for the function is on the same line as the opening brace or the
// first statement in the function, so make sure they're on the same
// line irrespective of our usual style guide.
static void B(void)
{ atomic_puts("calling C");
  C();
  atomic_puts("finished C");
}

static void A(void)
{ atomic_puts("calling B");
  B();
  atomic_puts("finished B");
}

int main(void) {
  atomic_puts("calling A");
  A();
  atomic_puts("finished A");
  return 0;
}
