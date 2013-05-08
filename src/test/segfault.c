/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include <stdlib.h>

int main(int argc, char *argv[]) {
	*((int*)rand()) = rand();
	return 0;
}
