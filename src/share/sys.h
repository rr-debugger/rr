#ifndef SYS_H_
#define SYS_H_

#include <stdio.h>
#include <signal.h>
#include <unistd.h>

#include "types.h"

void sys_close(int fd);
FILE* sys_fopen(const char* path, const char* mode);
void sys_fclose(FILE* file);
pid_t sys_fork();
int sys_open_child_mem(pid_t child_tid);
void sys_kill(int pid, int msg);
void sys_exit();
void sys_setup_process();
void sys_start_trace(char* executable, char** fake_argv, char** envp);

void singlestep(struct context *ctx, int sig);
void goto_next_event(struct context *ctx);

long sys_ptrace(int request, pid_t pid, void* addr, void* data);
void sys_ptrace_setup(pid_t pid);
void sys_ptrace_singlestep(pid_t pid, int sig);
void sys_ptrace_sysemu(pid_t pid);
void sys_ptrace_sysemu_sig(pid_t pid, int sig);
void sys_ptrace_sysemu_singlestep(pid_t pid);
void sys_ptrace_traceme();
void sys_ptrace_cont(pid_t pid);
void sys_ptrace_syscall_sig(pid_t pid, int sig);
unsigned long sys_ptrace_getmsg(pid_t pid);
void sys_ptrace_getsiginfo(pid_t pid, siginfo_t* sig);
void sys_ptrace_detatch(pid_t pid);
void sys_ptrace_syscall(pid_t pid);

pid_t sys_waitpid(pid_t pid, int *status);
pid_t sys_waitpid_nonblock(pid_t pid, int *status);
void sys_fcntl(int fd, int option, pid_t pid);
void sys_fcntl_f_setown(int fd, pid_t pid);
void sys_fcntl_f_setfl_o_async(int fd);

void* sys_mmap(void* addr, size_t length, int prot, int flags, int fd, off_t offset);
void* sys_malloc(int size);
void* sys_malloc_zero(int size);
void sys_free(void** ptr);
void sys_setpgid(pid_t pid, pid_t pgid);

#endif /* SYS_H_ */
