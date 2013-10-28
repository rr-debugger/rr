/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include "rrutil.h"

static void C(void) {
	atomic_puts("in C");
}

static void B(void) {
	atomic_puts("calling C");
	C();
	atomic_puts("finished C");
}

static void A(void) {
	atomic_puts("calling B");
	B();
	atomic_puts("finished B");
}

int main(void) {

	atomic_puts("calling A");
	A();
	atomic_puts("finished A");
	return 0;
}
