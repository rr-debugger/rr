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
void sys_start_trace(const char* executable, char** fake_argv, char** envp);

void sys_ptrace_setup(Task* t);
/* Return zero on success, -1 on error. */
unsigned long sys_ptrace_getmsg(Task* t);
void sys_ptrace_getsiginfo(Task* t, siginfo_t* sig);
void sys_ptrace_detach(pid_t pid);

void sys_fcntl(int fd, int cmd, long arg1);

#endif /* SYS_H_ */
