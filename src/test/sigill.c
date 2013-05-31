/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include <assert.h>
#include <stdio.h>

int main(int argc, char *argv[]) {
	puts("running privileged instruction ...");
	__asm__ ("ud2");
	assert("should have terminated!" && 0);
	return 0;
}
