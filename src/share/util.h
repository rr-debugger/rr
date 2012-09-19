#ifndef UTIL_H_
#define UTIL_H_

#include <stddef.h>
#include <stdio.h>
#include <sys/user.h>

#include "types.h"
#include "../share/config.h"


#define GET_PTRACE_EVENT(status)	 		((0xFF0000 & status) >> 16)


char* get_inst(pid_t pid, int eip_offset, int* opcode_size);
void print_inst(pid_t tid);
void print_syscall(struct context *ctx, struct trace *trace);
void get_eip_info(pid_t tid);
int check_if_mapped(struct context *ctx, void *start, void *end);
int compare_register_files(char* name1, struct user_regs_struct* reg1, char* name2, struct user_regs_struct* reg2, int print, int stop);
uint64_t str2ull(const char* start, size_t max_size);
long int str2li(const char* start, size_t max_size);
void read_line(FILE* file, char* buf, int size, char* name);

void print_register_file_tid(pid_t tid);
char* syscall_to_str(int syscall);

int signal_pending(int status);

struct current_state_buffer {
	pid_t pid;
	struct user_regs_struct regs;
	int code_size;
	long* code_buffer;
	long* start_addr;
};

void inject_code(struct current_state_buffer* buf, char* code);


#endif /* UTIL_H_ */
