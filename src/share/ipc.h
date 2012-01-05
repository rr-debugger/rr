#ifndef __IPC_H__
#define __IPC_H__

#include <sys/user.h>

#include "types.h"

void read_child_registers(int child_id, struct user_regs_struct* regs);
long read_child_code(pid_t pid, void* addr);
long read_child_data_word(pid_t pid, void* addr);
void* read_child_data(struct context *ctx, size_t size, uintptr_t addr);
void* read_child_data_checked(struct context *ctx, ssize_t size, uintptr_t addr, ssize_t *read_bytes);



void write_child_code(pid_t pid, void* addr, long code);
void write_child_registers(int child_id, struct user_regs_struct* regs);
void write_child_data_n(pid_t tid, size_t size, long int addr, void* data);
void write_child_data(struct context *ctx, const size_t size, void *addr, void *data);


/* access functions to child registers */
long int read_child_eax(pid_t child_id);
long int read_child_ebx(pid_t child_id);
long int read_child_ecx(pid_t child_id);
long int read_child_edx(pid_t child_id);
long int read_child_esi(pid_t child_id);
long int read_child_edi(pid_t child_id);
long int read_child_ebp(pid_t child_id);
long int read_child_esp(pid_t child_id);
long int read_child_eip(pid_t child_id);
long int read_child_orig_eax(pid_t child_id);


void write_child_eax(int tid, long int val);
void write_child_ebx(int tid, long int val);
void write_child_ecx(int tid, long int val);
void write_child_edx(int tid, long int val);
void write_child_edi(int tid, long int val);
void write_child_ebp(int tid, long int val);


char* read_child_str(pid_t pid, long int addr);
void* read_child_data_tid(pid_t tid, size_t size, long int addr);

#endif /* __IPC_H__ */
