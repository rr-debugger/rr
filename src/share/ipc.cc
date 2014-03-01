/* -*- Mode: C++; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

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

static long read_child_word(pid_t tid, byte* addr, int ptrace_op)
{
	CHECK_ALIGNMENT(addr);

	/* set errno to 0 to check if the read was successful */errno = 0;

	long tmp = ptrace(__ptrace_request(ptrace_op), tid, addr, 0);

	if (errno != 0) {
		log_err("Read of word %p from child returned %ld; dumping map",
			addr, tmp);
		/* TODO: fix this function to take a |task*| param,
		 * and use |print_process_mmap()|here.*/
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

long read_child_code(pid_t tid, byte* addr)
{
	return read_child_word(tid, addr, PTRACE_PEEKTEXT);
}

long read_child_data_word(Task* t, byte* addr)
{
	return read_child_word(t->tid, addr, PTRACE_PEEKDATA);
}

#define READ_SIZE (sizeof(long))

ssize_t checked_pread(Task* t, byte* buf, size_t size, off_t offset) {
	errno = 0;
	ssize_t read = pread(t->child_mem_fd, buf, size, offset);
	if (read < 0) {
		return read;
	}

	// We open the child_mem_fd just after being notified of
	// exec(), when the Task is created.  Trying to read from that
	// fd seems to return 0 with errno 0.  Reopening the mem fd
	// allows the pread to succeed.  It seems that the first mem
	// fd we open, very early in exec, refers to some resource
	// that's different than the one we see after reopening the
	// fd, after exec.
	//
	// TODO create the fd on demand and remove this workaround.
	if (read == 0 && errno == 0) {
		sys_close(t->child_mem_fd);
		t->child_mem_fd = sys_open_child_mem(t);
		read = pread(t->child_mem_fd, buf, size, offset);
	}

	if (read < ssize_t(size)) { // fill the remainder with zeros
		memset(buf + read, 0, size - read);
		read = size;
	}

	assert(read == ssize_t(size));

	return read;

}

void* read_child_data_checked(Task *t, size_t size, byte* addr, ssize_t *read_bytes)
{
	//assert(check_if_mapped(t, addr, addr + size));

	byte *buf = (byte*)malloc(size);
	/* if pread fails: do the following:   echo 0 > /proc/sys/kernel/yama/ptrace_scope */
	*read_bytes = checked_pread(t, buf, size, PTR_TO_OFF_T(addr));

	return buf;
}

void read_child_usr(Task *t, void *dest, void *src, size_t size) {
	ssize_t bytes_read = pread(t->child_mem_fd, dest, size, PTR_TO_OFF_T(src));
	assert_exec(t, bytes_read == ssize_t(size),
		    "Reading %p: expected %d bytes, but got %d",
		    src, size, bytes_read);
}

void* read_child_data(Task *t, size_t size, byte* addr)
{
	byte* buf = (byte*)malloc(size);
	read_child_data_direct(t, (byte*)addr, size, buf);
	return buf;
}

void read_child_data_direct(Task *t, const byte* addr, size_t size, byte* buf)
{
	ssize_t read_bytes = checked_pread(t, buf, size, PTR_TO_OFF_T(addr));
	assert_exec(t, read_bytes == ssize_t(size),
		    "Expected to read %u bytes, but read %d", size, read_bytes);
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
