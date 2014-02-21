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
pid_t sys_fork(void);
int sys_open_child_mem(Task* t);
void sys_kill(int pid, int msg);
void sys_exit(void);
void sys_start_trace(const char* executable, char** fake_argv, char** envp);

void goto_next_event(Task *t);

void sys_ptrace(Task* t, int request, void* addr, void* data);
void sys_ptrace_setup(Task* t);
void sys_ptrace_singlestep(Task* t);
void sys_ptrace_singlestep_sig(Task* t, int sig);
void sys_ptrace_sysemu(Task* t);
void sys_ptrace_sysemu_singlestep(Task* t);
void sys_ptrace_traceme(void);
void sys_ptrace_cont(pid_t pid);
void sys_ptrace_cont_sig(pid_t pid, int sig);
void sys_ptrace_syscall_sig(Task* pid, int sig);
/* Return zero on success, -1 on error. */
int sys_ptrace_peekdata(pid_t pid, long addr, long* value);
unsigned long sys_ptrace_getmsg(Task* t);
void sys_ptrace_getsiginfo(Task* t, siginfo_t* sig);
void sys_ptrace_detach(pid_t pid);
void sys_ptrace_syscall(Task* t);

/**
 * Block until the status of |pid| changes.  Write the new status into
 * |*status|.  Return true if successful, false if interrupted.
 */
bool sys_waitpid(pid_t pid, int *status);
pid_t sys_waitpid_nonblock(pid_t pid, int *status);
void sys_fcntl(int fd, int cmd, long arg1);

#endif /* SYS_H_ */
