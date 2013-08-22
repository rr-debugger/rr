/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include "rrutil.h"

#include <errno.h>
#include <syscall.h>

int main(int argc, char *argv[]) {
	int ret = syscall(-10);
	test_assert(-1 == ret && ENOSYS == errno);
	return 0;
}
