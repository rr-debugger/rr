/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include "ipc.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>

#include "dbg.h"
#include "sys.h"
#include "task.h"
#include "trace.h"
#include "util.h"

#define PTR_TO_OFF_T(_p) (off_t)(uintptr_t)(_p)

void read_child_registers(pid_t pid, struct user_regs_struct* regs)
{
	sys_ptrace(PTRACE_GETREGS, pid, NULL, regs);
}

size_t set_child_data(struct context *ctx)
{
	size_t size;
	void* rec_addr;
	void* data = read_raw_data(&(ctx->trace), &size, &rec_addr);
	if (data != NULL && size > 0) {
		write_child_data(ctx, size, rec_addr, data);
		sys_free((void**) &data);
	}
	return size;
}

void set_return_value(struct context* context)
{
	struct user_regs_struct r;
	read_child_registers(context->tid, &r);
	r.eax = context->trace.recorded_regs.eax;
	write_child_registers(context->tid, &r);
}

static long read_child_word(pid_t tid, void *addr, int ptrace_op)
{
	CHECK_ALIGNMENT(addr);

	/* set errno to 0 to check if the read was successful */errno = 0;

	long tmp = ptrace(ptrace_op, tid, addr, 0);

	if (errno != 0) {
		log_err("Read of word %p from child returned %ld; dumping map",
			addr, tmp);

		char path[64];
		FILE* file;
		bzero(path, 64);
		sprintf(path, "/proc/%d/maps", tid);
		if ((file = fopen(path, "r")) < 0) {
			log_err("Error reading child memory maps\n");
		}

		int c = getc(file);
		while (c != EOF) {
			putchar(c);
			c = getc(file);
		}

		fatal("Goodbye");
	}
	return tmp;
}

long read_child_code(pid_t tid, void *addr)
{
	return read_child_word(tid, addr, PTRACE_PEEKTEXT);
}

long read_child_data_word(pid_t tid, void *addr)
{
	return read_child_word(tid, addr, PTRACE_PEEKDATA);
}

void write_child_main_registers(pid_t tid, struct user_regs_struct *regs) {
	struct user_regs_struct regs0;
	read_child_registers(tid,&regs0);
	regs0.eax = regs->eax;
	regs0.ebx = regs->ebx;
	regs0.ecx = regs->ecx;
	regs0.edi = regs->edi;
	regs0.edx = regs->edx;
	regs0.eflags = regs->eflags;
	regs0.eip = regs->eip;
	regs0.esi = regs->esi;
	regs0.esp = regs->esp;
	regs0.orig_eax = regs->orig_eax;
	write_child_registers(tid,&regs0);
}

void write_child_segment_registers(pid_t tid, struct user_regs_struct *regs) {
	struct user_regs_struct regs0;
	read_child_registers(tid,&regs0);
	regs0.xcs = regs->xcs;
	regs0.xds = regs->xds;
	regs0.xes = regs->xes;
	regs0.xfs = regs->xfs;
	regs0.xgs = regs->xgs;
	regs0.xss = regs->xss;
	write_child_registers(tid,&regs0);
}

void write_child_registers(pid_t pid, struct user_regs_struct *regs)
{
	sys_ptrace(PTRACE_SETREGS, pid, NULL, regs);
}

void write_child_code(pid_t pid, void* addr, long code)
{
	CHECK_ALIGNMENT(addr);

	sys_ptrace(PTRACE_POKETEXT, pid, addr, (void*) code);
}

void write_child_data_word(pid_t pid, void *addr, uintptr_t data)
{
	CHECK_ALIGNMENT(addr);
	sys_ptrace(PTRACE_POKEDATA, pid, addr, (void*)data);
}

long int read_child_syscall(int child_id)
{
	struct user_regs_struct regs;
	sys_ptrace(PTRACE_GETREGS, child_id, NULL, &regs);
	return regs.orig_eax;
}

long int get_ret_syscall(int child_id)
{
	struct user_regs_struct regs;
	sys_ptrace(PTRACE_GETREGS, child_id, NULL, &regs);
	return regs.eax;
}

/* Rad child registers */

long int read_child_eip(pid_t child_id)
{
	struct user_regs_struct regs;
	sys_ptrace(PTRACE_GETREGS, child_id, NULL, &regs);
	return regs.eip;
}

long int read_child_orig_eax(int child_id)
{
	struct user_regs_struct regs;
	sys_ptrace(PTRACE_GETREGS, child_id, NULL, &regs);
	return regs.orig_eax;
}

long int read_child_eax(int child_id)
{
	struct user_regs_struct regs;
	sys_ptrace(PTRACE_GETREGS, child_id, NULL, &regs);
	return regs.eax;
}

long int read_child_ebx(int child_id)
{
	struct user_regs_struct regs;
	sys_ptrace(PTRACE_GETREGS, child_id, NULL, &regs);
	return regs.ebx;
}

long int read_child_ecx(int child_id)
{
	struct user_regs_struct regs;
	sys_ptrace(PTRACE_GETREGS, child_id, NULL, &regs);
	return regs.ecx;
}

long int read_child_edx(int child_id)
{
	struct user_regs_struct regs;
	sys_ptrace(PTRACE_GETREGS, child_id, NULL, &regs);
	return regs.edx;
}

long int read_child_esi(int child_id)
{
	struct user_regs_struct regs;
	sys_ptrace(PTRACE_GETREGS, child_id, NULL, &regs);
	return regs.esi;
}

long int read_child_edi(int child_id)
{
	struct user_regs_struct regs;
	sys_ptrace(PTRACE_GETREGS, child_id, NULL, &regs);
	return regs.edi;
}

long int read_child_ebp(int child_id)
{
	struct user_regs_struct regs;
	sys_ptrace(PTRACE_GETREGS, child_id, NULL, &regs);
	return regs.ebp;
}

long int read_child_esp(int child_id)
{
	struct user_regs_struct regs;
	sys_ptrace(PTRACE_GETREGS, child_id, NULL, &regs);
	return regs.esp;
}

void write_child_eax(int tid, long int val)
{
	struct user_regs_struct regs;
	read_child_registers(tid, &regs);
	regs.eax = val;
	write_child_registers(tid, &regs);
}

void write_child_ebx(int tid, long int val)
{
	struct user_regs_struct regs;
	read_child_registers(tid, &regs);
	regs.ebx = val;
	write_child_registers(tid, &regs);
}

void write_child_ecx(int tid, long int val)
{
	struct user_regs_struct regs;
	read_child_registers(tid, &regs);
	regs.ecx = val;
	write_child_registers(tid, &regs);
}

void write_child_edx(int tid, long int val)
{
	struct user_regs_struct regs;
	read_child_registers(tid, &regs);
	regs.edx = val;
	write_child_registers(tid, &regs);
}

void write_child_edi(int tid, long int val)
{
	struct user_regs_struct regs;
	read_child_registers(tid, &regs);
	regs.edi = val;
	write_child_registers(tid, &regs);
}

void write_child_ebp(int tid, long int val)
{
	struct user_regs_struct regs;
	read_child_registers(tid, &regs);
	regs.ebp = val;
	write_child_registers(tid, &regs);
}

void write_child_esi(int tid, long int val)
{
	struct user_regs_struct regs;
	read_child_registers(tid, &regs);
	regs.esi = val;
	write_child_registers(tid, &regs);
}

void write_child_eip(int tid, long int val)
{
	struct user_regs_struct regs;
	read_child_registers(tid, &regs);
	regs.eip = val;
	write_child_registers(tid, &regs);
}

#define READ_SIZE (sizeof(long))

void* read_child_data_tid(pid_t tid, size_t size, void* addr)
{

	int i, padding = 0;
	long tmp;
	void* data = sys_malloc(size);

	int offset = ((uintptr_t) addr) & 0x3;
	if (offset) {
		tmp = read_child_data_word(tid,
					   (void*)((uintptr_t)addr & ~0x3));
		padding = READ_SIZE - offset;
		memcpy(data, ((void*) (&tmp)) + offset, padding);
	}

	for (i = padding; i < size; i += READ_SIZE) {
		tmp = read_child_data_word(tid, (void*)(addr + i));
		memcpy(data + i, &tmp, READ_SIZE);
	}
	/* make sure we no not return more than required */
	return data;
}

ssize_t checked_pread(struct context *ctx, void *buf, size_t size, off_t offset) {
	errno = 0;
	ssize_t read = pread(ctx->child_mem_fd, buf, size, offset);
	if (read < 0) {
		return read;
	}

	// for some reason reading from the child process requires to re-open the fd
	// who knows why??
	if (read == 0 && errno == 0) {
		sys_close(ctx->child_mem_fd);
		ctx->child_mem_fd = sys_open_child_mem(ctx->tid);
		read = pread(ctx->child_mem_fd, buf, size, offset);
	}

	if (read < size) { // fill the remainder with zeros
		memset(buf + read,0,size - read);
		read = size;
	}

	assert(read == size);

	return read;

}

void* read_child_data_checked(struct context *ctx, size_t size, void* addr, ssize_t *read_bytes)
{
	//assert(check_if_mapped(ctx, addr, addr + size));

	void *buf = sys_malloc(size);
	/* if pread fails: do the following:   echo 0 > /proc/sys/kernel/yama/ptrace_scope */
	*read_bytes = checked_pread(ctx, buf, size, PTR_TO_OFF_T(addr));

	return buf;
}

void read_child_usr(struct context *ctx, void *dest, void *src, size_t size) {
	ssize_t bytes_read = pread(ctx->child_mem_fd, dest, size, PTR_TO_OFF_T(src));
	(void)bytes_read;
	assert(bytes_read == size);
}

void* read_child_data(struct context *ctx, size_t size, void* addr)
{
	void *buf = sys_malloc(size);
	/* if pread fails: do the following:   echo 0 > /proc/sys/kernel/yama/ptrace_scope */
	ssize_t read_bytes = checked_pread(ctx, buf, size, PTR_TO_OFF_T(addr));
	if (read_bytes != size) {
		sys_free(&buf);
		buf = read_child_data_tid(ctx->tid, size, addr);
		printf("reading from: %p demanded: %u  read %u  event: %d\n", addr, size, read_bytes, ctx->event);
		perror("warning: reading from child process: ");
		printf("try the following: echo 0 > /proc/sys/kernel/yama/ptrace_scope\n");
	}

	return buf;
}

/**
 * A more conservative way for reading data from the child,
 * this method doesn't use the memory file descriptor.
 */
void read_child_buffer(pid_t child_pid, uintptr_t address, size_t length, char *buffer){
	const int long_size = sizeof(long);
	char *laddr;
    int i, j;
    union u {
		long val;
		char chars[long_size];
    } data;
    i = 0;
    j = length / long_size;
    laddr = buffer;
    while(i < j) {
        data.val = ptrace(PTRACE_PEEKDATA, child_pid, address + i * 4, NULL);
        memcpy(laddr, data.chars, long_size);
        ++i;
        laddr += long_size;
    }
    j = length % long_size;
    if(j != 0) {
        data.val = ptrace(PTRACE_PEEKDATA, child_pid, address + i * 4, NULL);
        memcpy(laddr, data.chars, j);
    }
    buffer[length] = '\0';
}

/**
 * A more conservative way for writing data from the child,
 * this method doesn't use the memory file descriptor.
 */
void write_child_buffer(pid_t child_pid, uintptr_t address, size_t length, char *buffer){
	const int long_size = sizeof(long);
	char *laddr;
    int i, j;
    union u {
            long val;
            char chars[long_size];
    }data;
    i = 0;
    j = length / long_size;
    laddr = buffer;
    while(i < j) {
        memcpy(data.chars, laddr, long_size);
        ptrace(PTRACE_POKEDATA, child_pid,
        		address + i * 4, data.val);
        ++i;
        laddr += long_size;
    }
    j = length % long_size;
    if(j != 0) {
        memcpy(data.chars, laddr, j);
        ptrace(PTRACE_POKEDATA, child_pid,
        		address + i * 4, data.val);
    }
}

char* read_child_str(pid_t pid, void* addr)
{
	char *tmp, *str;
	int i, idx = 0;
	int buffer_size = 256;

	str = sys_malloc(buffer_size);

	while (1) {

		if (idx + READ_SIZE >= buffer_size) {
			buffer_size *= 2;
			str = realloc(str, buffer_size);
		}

		tmp = read_child_data_tid(pid, READ_SIZE, addr + idx);
		memcpy(str + idx, tmp, READ_SIZE);
		sys_free((void**) &tmp);

		for (i = 0; i < READ_SIZE; i++) {
			if (str[idx + i] == '\0') {
				return str;
			}
		}

		idx += READ_SIZE;
	}assert(1==0);
	return 0;
}

void write_child_data_n(pid_t tid, size_t size, void* addr, const void* data)
{
	int start_offset = (uintptr_t)addr & 0x3;
	int end_offset = ((uintptr_t)addr + size) & 0x3;

	size_t write_size = size;
	void* write_data = sys_malloc(size + 2 * READ_SIZE);
	void* write_addr = (void*) addr;

	if (start_offset) {
		void* aligned_start = (void*)((uintptr_t)addr & ~0x3);
		long int word = read_child_data_word(tid, aligned_start);
		memcpy(write_data, &word, READ_SIZE);
		write_size += start_offset;
		write_addr = aligned_start;
	}

	if (end_offset) {
		void* aligned_end = (void*)(((uintptr_t)addr + size) & ~0x3);
		long int word = read_child_data_word(tid, aligned_end);
		write_size += READ_SIZE - end_offset;
		unsigned long buffer_addr = ((unsigned long) write_data + start_offset + size) & ~0x3;
		memcpy((void*) buffer_addr, &word, READ_SIZE);
	}

	assert(write_size % 4 == 0);
	memcpy(write_data + start_offset, data, size);

	int i;
	for (i = 0; i < write_size; i += READ_SIZE) {
		uint32_t word = *(uint32_t*) (write_data + i);
		write_child_data_word(tid, write_addr + i, word);
	}

	free(write_data);
}

void write_child_data(struct context *ctx, size_t size, void *addr,
		      const void *data)
{
	ssize_t written = pwrite(ctx->child_mem_fd, data, size, PTR_TO_OFF_T(addr));
	if (written != size) {
		write_child_data_n(ctx->tid, size, addr, data);
	}
}

void memcpy_child(struct context *ctx, void *dest, void *src, int size)
{
	void *tmp = read_child_data(ctx, size, src);
	write_child_data(ctx, size, dest, tmp);
	free(tmp);
}
