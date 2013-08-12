/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <syscall.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
	int ret = syscall(-10);
	assert(-1 == ret && ENOSYS == errno);
	return 0;
}
