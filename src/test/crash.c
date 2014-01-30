/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include "rrutil.h"

int main(int argc, char *argv[]) {
	volatile int* p = NULL;
	*p = 42;
	test_assert("Not reached" && 0);
	return 0;
}
