/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#ifndef UTIL_H_
#define UTIL_H_

#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/user.h>

#include "types.h"
#include "../share/config.h"

#define GET_PTRACE_EVENT(status) \
	((0xFF0000 & status) >> 16)
#define SYSCALL_FAILED(eax) \
	(-ERANGE <= (int)(eax) && (int)(eax) < 0)
#define SYSCALL_WILL_RESTART(eax) \
	(ERESTART_RESTARTBLOCK == (eax) || ERESTARTNOINTR == (eax))

#ifndef PTRACE_EVENT_SECCOMP
#define PTRACE_O_TRACESECCOMP			0x00000080
#define PTRACE_EVENT_SECCOMP_OBSOLETE	8 // ubuntu 12.04
#define PTRACE_EVENT_SECCOMP			7 // ubuntu 12.10 and future kernels
#endif

#define ALEN(_arr) (sizeof(_arr) / (sizeof(_arr[0])))

#define MAX(_a, _b) ((_a) > (_b) ? (_a) : (_b))
#define MIN(_a, _b) ((_a) < (_b) ? (_a) : (_b))

char* get_inst(pid_t pid, int eip_offset, int* opcode_size);
bool is_write_mem_instruction(pid_t pid, int eip_offset, int* opcode_size);
void emulate_child_inst(struct context * ctx, int eip_offset);
void print_inst(pid_t tid);
void print_syscall(struct context *ctx, struct trace_frame *trace);
void get_eip_info(pid_t tid);
int check_if_mapped(struct context *ctx, void *start, void *end);
int compare_register_files(char* name1, struct user_regs_struct* reg1, char* name2, struct user_regs_struct* reg2, int print, int stop);
uint64_t str2ull(const char* start, size_t max_size);
long int str2li(const char* start, size_t max_size);
void * str2x(const char* start, size_t max_size);
void read_line(FILE* file, char* buf, int size, char* name);
void add_scratch(void *ptr, int size);
int overall_scratch_size();
void add_protected_map(struct context *ctx, void *start);
bool is_protected_map(struct context *ctx, void *start);
void add_sig_handler(pid_t tid, unsigned int signum, struct sigaction * sa);
struct sigaction * get_sig_handler(pid_t tid, unsigned int signum);

void print_register_file_tid(pid_t tid);
void print_register_file(struct user_regs_struct* regs);
void print_process_memory(struct context * ctx, char * filename);
void checksum_process_memory(struct context * ctx);
void validate_process_memory(struct context * ctx);
void * get_mmaped_region_end(struct context * ctx, void * mmap_start);
char * get_mmaped_region_filename(struct context * ctx, void * mmap_start);
int get_memory_size(struct context * ctx);
char * syscall_to_str(int syscall);

int signal_pending(int status);


struct current_state_buffer {
	pid_t pid;
	struct user_regs_struct regs;
	int code_size;
	long* code_buffer;
	long* start_addr;
};

void inject_code(struct current_state_buffer* buf, char* code);
int inject_and_execute_syscall(struct context * ctx, struct user_regs_struct * call_regs);
void mprotect_child_region(struct context * ctx, void * addr, int prot);

#endif /* UTIL_H_ */
