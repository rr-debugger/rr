/* -*- Mode: C++; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#ifndef __IPC_H__
#define __IPC_H__

/* XXX this should be a global -D define */
#define _FILE_OFFSET_BITS 64

#include <sys/user.h>

#include "types.h"

struct task;

void read_child_registers(struct task* t, struct user_regs_struct* regs);
long read_child_code(pid_t pid, byte* addr);
long read_child_data_word(struct task* t, byte* addr);
void* read_child_data(struct task *t, size_t size, byte* addr);
void read_child_usr(struct task *t, void *dest, void *src, size_t size);
void* read_child_data_checked(struct task *t, size_t size, byte* addr, ssize_t *read_bytes);
ssize_t checked_pread(struct task* t, byte* buf, size_t size, off_t offset);
void memcpy_child(struct task* t, void* dest, void* src, int size);

void write_child_code(struct task* t, void* addr, long code);
void write_child_registers(struct task* t, struct user_regs_struct* regs);
void write_child_data_n(struct task* t, ssize_t size, byte* addr,
			const byte* data);
void write_child_data(struct task* t, ssize_t size, byte* addr,
		      const byte* data);
size_t set_child_data(struct task* t);

// XXX rewrite me
long int read_child_eax(struct task* t);
long int read_child_ebx(struct task* t);
long int read_child_ecx(struct task* t);
long int read_child_edx(struct task* t);
long int read_child_esi(struct task* t);
long int read_child_edi(struct task* t);
long int read_child_ebp(struct task* t);
long int read_child_esp(struct task* t);
long int read_child_eip(struct task* t);
long int read_child_orig_eax(struct task* t);


void write_child_eax(struct task* t, long int val);
void write_child_ebx(struct task* t, long int val);
void write_child_ecx(struct task* t, long int val);
void write_child_edx(struct task* t, long int val);
void write_child_edi(struct task* t, long int val);
void write_child_ebp(struct task* t, long int val);
void set_return_value(struct task* context);


char* read_child_str(struct task* t, byte* addr);

#endif /* __IPC_H__ */
