/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include <stdio.h>

static void C() {
	puts("in C");
}

static void B() {
	puts("calling C");
	C();
	puts("finished C");
}

static void A() {
	puts("calling B");
	B();
	puts("finished B");
}

int main() {
	puts("calling A");
	A();
	puts("finished A");
	fflush(stdout);
	return 0;
}
