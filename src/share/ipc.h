/* -*- Mode: C++; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#ifndef __IPC_H__
#define __IPC_H__

/* XXX this should be a global -D define */
#define _FILE_OFFSET_BITS 64

#include <sys/user.h>

#include "types.h"

class Task;

void read_child_registers(Task* t, struct user_regs_struct* regs);
long read_child_code(pid_t pid, byte* addr);
long read_child_data_word(Task* t, byte* addr);
void* read_child_data(Task *t, size_t size, byte* addr);
void read_child_usr(Task *t, void *dest, void *src, size_t size);
void* read_child_data_checked(Task *t, size_t size, byte* addr, ssize_t *read_bytes);
ssize_t checked_pread(Task* t, byte* buf, size_t size, off_t offset);
void memcpy_child(Task* t, void* dest, void* src, int size);

void write_child_code(Task* t, void* addr, long code);
void write_child_registers(Task* t, struct user_regs_struct* regs);
void write_child_data_n(Task* t, ssize_t size, byte* addr,
			const byte* data);
void write_child_data(Task* t, ssize_t size, byte* addr,
		      const byte* data);
size_t set_child_data(Task* t);

// XXX rewrite me
long int read_child_eax(Task* t);
long int read_child_ebx(Task* t);
long int read_child_ecx(Task* t);
long int read_child_edx(Task* t);
long int read_child_esi(Task* t);
long int read_child_edi(Task* t);
long int read_child_ebp(Task* t);
long int read_child_esp(Task* t);
long int read_child_eip(Task* t);
long int read_child_orig_eax(Task* t);


void write_child_eax(Task* t, long int val);
void write_child_ebx(Task* t, long int val);
void write_child_ecx(Task* t, long int val);
void write_child_edx(Task* t, long int val);
void write_child_edi(Task* t, long int val);
void write_child_ebp(Task* t, long int val);
void set_return_value(Task* context);


char* read_child_str(Task* t, byte* addr);

#endif /* __IPC_H__ */
