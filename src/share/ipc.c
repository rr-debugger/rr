#define _FILE_OFFSET_BITS 64

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>

#include "sys.h"
#include "util.h"

#define CHECK_ALIGNMENT(addr) assert (((long int)(addr) & 0x3) == 0);

void read_child_registers(pid_t pid, struct user_regs_struct* regs)
{
	sys_ptrace(PTRACE_GETREGS, pid, NULL, regs);
}

static long read_child_data_word(pid_t tid, void *addr)
{
	CHECK_ALIGNMENT(addr);

	/* set errno to 0 to check if the read was successful */errno = 0;

	long tmp = ptrace(PTRACE_PEEKDATA, tid, addr, 0);

	if (errno != 0) {
		perror("error reading word from child -- bailing out");
		fprintf(stderr, "read failed at addr %p\n", addr);
		fprintf(stderr, "printing mapped memory region: we read %ld\n", tmp);

		char path[64];
		FILE* file;
		bzero(path, 64);
		sprintf(path, "/proc/%d/maps", tid);
		if ((file = fopen(path, "r")) < 0) {
			perror("error reading child memory maps\n");
		}

		int c = getc(file);
		while (c != EOF) {
			putchar(c);
			c = getc(file);
		}

		assert(1==0);

		//sys_exit();
	}
	return tmp;
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

static void write_child_data_word(pid_t pid, void *addr, void *data)
{
	CHECK_ALIGNMENT(addr);
	sys_ptrace(PTRACE_POKEDATA, pid, addr, data);
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

void* read_child_data_tid(pid_t tid, size_t size, void *addr)
{

	int i, padding = 0;
	long tmp;
	void* data = sys_malloc(size);

	int offset = ((uintptr_t) addr) & 0x3;
	if (offset) {
		tmp = read_child_data_word(tid, ((uintptr_t) addr) & ~0x3);
		padding = READ_SIZE - offset;
		memcpy(data, ((void*) (&tmp)) + offset, padding);
	}

	for (i = padding; i < size; i += READ_SIZE) {
		tmp = read_child_data_word(tid, addr + i);
		memcpy(data + i, &tmp, READ_SIZE);
	}
	/* make sure we no not return more than required */
	return data;
}

static size_t checked_pread(struct context *ctx, void *buf, size_t size,off_t offset) {

	size_t read = pread(ctx->child_mem_fd, buf, size, offset);
	// for some reason reading from the child process requires to re-open the fd
	// who knows why??
	if (read == 0 && errno == 0) {
		sys_close(ctx->child_mem_fd);
		ctx->child_mem_fd = sys_open_child_mem(ctx->child_tid);
	}

	return pread(ctx->child_mem_fd, buf, size, offset);

}

void* read_child_data_checked(struct context *ctx, ssize_t size, uintptr_t addr, ssize_t *read_bytes)
{
	//assert(check_if_mapped(ctx, addr, addr + size));

	void *buf = sys_malloc(size);
	/* if pread fails: do the following:   echo 0 > /proc/sys/kernel/yama/ptrace_scope */
	*read_bytes = checked_pread(ctx,buf,size,addr);

	return buf;
}

void read_child_usr(struct context *ctx, void *dest, void *src, size_t size) {
	assert(pread(ctx->child_mem_fd, dest, size, (uintptr_t)src) == size);
}

void* read_child_data(struct context *ctx, ssize_t size, uintptr_t addr)
{
	void *buf = sys_malloc(size);
	/* if pread fails: do the following:   echo 0 > /proc/sys/kernel/yama/ptrace_scope */
	ssize_t read_bytes = checked_pread(ctx,buf,size,addr);
	if (read_bytes != size) {
		free(buf);
		buf = read_child_data_tid(ctx->child_tid,size,addr);
		printf("reading from: %x demanded: %u  read %u  event: %d\n", addr, size, read_bytes, ctx->event);
		perror("warning: reading from child process: ");
		printf("try the following: echo 0 > /proc/sys/kernel/yama/ptrace_scope\n");
	}

	return buf;
}

/**
 * A more conservative way for reading data from the child,
 * this method doesn't use the memory file descriptor.
 */
void read_child_buffer(pid_t child_pid, uintptr_t address, ssize_t length, char *buffer){
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

char* read_child_str(pid_t pid, long int addr)
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

void write_child_data_n(pid_t tid, const size_t size, long int addr, void* data)
{

	int start_offset = addr & 0x3;
	int end_offset = (addr + size) & 0x3;

	size_t write_size = size;
	void* write_data = sys_malloc(size + 2 * READ_SIZE);
	void* write_addr = (void*) addr;

	if (start_offset) {
		long int word = read_child_data_word(tid, addr & ~0x3);
		memcpy(write_data, &word, READ_SIZE);
		write_size += start_offset;
		write_addr = (void*) (addr & ~0x3);
	}

	if (end_offset) {
		long int word = read_child_data_word(tid, (addr + size) & ~0x3);
		write_size += READ_SIZE - end_offset;
		unsigned long buffer_addr = ((unsigned long) write_data + start_offset + size) & ~0x3;
		memcpy((void*) buffer_addr, &word, READ_SIZE);
	}

	assert(write_size % 4 == 0);
	memcpy(write_data + start_offset, data, size);

	int i;
	for (i = 0; i < write_size; i += READ_SIZE) {
		uint32_t word = *(uint32_t*) (write_data + i);
		write_child_data_word(tid, write_addr + i, (void*) word);
	}

	free(write_data);
}

void write_child_data(struct context *ctx, const size_t size, void *addr, void *data)
{

	ssize_t written = pwrite(ctx->child_mem_fd, data, size, (off_t) addr);
	if (written != size) {
		write_child_data_n(ctx->child_tid, size, addr, data);
	}
}

void memcpy_child(struct context *ctx, void *dest, void *src, int size)
{
	void *tmp = read_child_data(ctx, size, src);
	write_child_data(ctx, size, dest, tmp);
	free(tmp);
}

