/* -*- Mode: C++; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#ifndef SYS_H_
#define SYS_H_

#include <stdio.h>
#include <signal.h>
#include <unistd.h>

#include <sys/stat.h>

#include "types.h"

class Task;

void sys_close(int filedes);
FILE* sys_fopen(const char* path, const char* mode);
int sys_open(const char* path, int flags, mode_t mode);
int sys_mkpath(const char *path, mode_t mode);
void sys_fclose(FILE* file);

void sys_fcntl(int fd, int cmd, long arg1);

#endif /* SYS_H_ */
