#include <assert.h>
#include <err.h>
#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/syscall.h>

#include "../share/types.h"

#include "sys.h"

#define CHECK_ALIGNMENT(addr) assert (((long int)(addr) & 0x3) == 0);

void read_child_registers(pid_t pid, struct user_regs_struct* regs)
{
	sys_ptrace(PTRACE_GETREGS, pid, NULL, regs);
}

long read_child_code(pid_t pid, void* addr)
{
	CHECK_ALIGNMENT(addr);

	long tmp;
	tmp = sys_ptrace(PTRACE_PEEKTEXT, pid, addr, 0);
	return tmp;
}

static long read_child_data_word(pid_t pid, long int addr)
{
	CHECK_ALIGNMENT(addr);

	long tmp;
	/* currently no error checking -- what if data-word == -1? */
	tmp = ptrace(PTRACE_PEEKDATA, pid, addr, 0);
	return tmp;
}

void write_child_registers(pid_t pid, struct user_regs_struct* regs)
{
	sys_ptrace(PTRACE_SETREGS, pid, NULL, regs);
}

void write_child_code(pid_t pid, void* addr, long code)
{
	CHECK_ALIGNMENT(addr);

	sys_ptrace(PTRACE_POKETEXT, pid, addr, (void*) code);
}

static void write_child_data_word(pid_t pid, void* addr, void* data)
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

void write_child_eip(int tid, long int val)
{
	struct user_regs_struct regs;
	read_child_registers(tid, &regs);
	regs.eip = val;
	write_child_registers(tid, &regs);
}

#define READ_SIZE (sizeof(long))

void* read_child_data_tid(pid_t tid, size_t size, long int addr)
{
	int i, offset, padding = 0;
	long tmp;
	void* data = sys_malloc(size);

	offset = addr & 0x3;
	if (offset) {
		tmp = read_child_data_word(tid, addr & ~0x3);
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

void* read_child_data(struct context *ctx, size_t size, uintptr_t addr)
{
	size_t bytes_read;
	void* data = sys_malloc(size);

	if ((bytes_read = pread64(ctx->child_mem_fd, data, size, addr)) < size) {
		assert(bytes_read >= 0);

		void* rest = read_child_data_tid(ctx->child_tid, size - bytes_read, addr + bytes_read);
		memcpy(data + bytes_read, rest, size - bytes_read);
		sys_free((void**) &rest);
	}
	/* make sure we no not return more than required */
	return data;
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
	}
	assert(1==0);
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
		memcpy(buffer_addr, &word, READ_SIZE);
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

