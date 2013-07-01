/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

/*
 * syscall_buffer.h
 *
 *  Created on: Nov 28, 2012
 *      Author: user
 */

#ifndef SYSCALL_BUFFER_H_
#define SYSCALL_BUFFER_H_

#define SYSCALL_BUFFER_LIB_FILENAME				"librr_syscall_buffer.so"

#define SYSCALL_BUFFER_CACHE_SIZE				((1 << 20) - sizeof(int)) /* Accounting for buffer[0] which holds size */
#define SYSCALL_BUFFER_CACHE_FILENAME_PREFIX 	"record_cache_"

#define RRCALL_map_syscall_buffer -42
#define __NR_rrcall_map_syscall_buffer (42 | RRCALL_BIT)
#define SYS_rrcall_map_syscall_buffer __NR_rrcall_map_syscall_buffer

/* Buffered syscalls need to be added here. Note: be careful of
 * syscalls that originate from wrapper internal code.
 *
 * FIXME/TODO: how do we detect this with syscalls that may or may not
 * be buffered depending on available space? */
#define SYSCALL_BUFFER_CALLSITE_IN_LIB(_eip, _ctx)			\
	(((long)(_eip) >= (long)((_ctx)->syscall_wrapper_start)		\
	  && (long)(_eip) <= (long)((_ctx)->syscall_wrapper_end)) &&	\
	((_ctx)->event == SYS_clock_gettime				\
	 || (_ctx)->event == SYS_gettimeofday				\
	 || (_ctx)->event == SYS_write					\
	 || (_ctx)->event == SYS_read					\
	 || (_ctx)->event == SYS_fstat64				\
	 || (_ctx)->event == SYS_lstat64				\
	 || (_ctx)->event == SYS_stat64					\
	 || (_ctx)->event == SYS_epoll_wait				\
	 || (_ctx)->event == SYS_socketcall				\
	 || (_ctx)->event == SYS_futex))

/**
 * The syscall buffer comprises an array of these (variable-length)
 * records.
 */
struct syscall_record {
	int syscall;
	/* Length of entire record: this struct plus extra recorded
	 * data stored inline after |ret|, not including padding. */
	size_t length;
	int ret;
	/* Extra recorded outparam data starts here. */
} __attribute__((__packed__));

/**
 * The ABI of the socketcall syscall is a nightmare; the first arg to
 * the kernel is the sub-operation, and the second argument is a
 * pointer to the args.  The args depend on the sub-op.
 */
struct socketcall_args {
	long args[3];
} __attribute__((packed));

/**
 * Return the amount of space that a record of |length| will occupy in
 * the buffer if committed, including padding.
 */
inline static int stored_record_size(size_t length)
{
	/* Round up to a whole number of 32-bit words. */
	return (length + sizeof(int) - 1) & ~(sizeof(int) - 1);
}

/**
 * Write the socket name that |tid| will use into |buf|, which is of
 * size |len|.
 */
inline static void prepare_syscallbuf_socket_addr(struct sockaddr_un* addr,
						  pid_t tid)
{
	memset(addr, 0, sizeof(*addr));
	addr->sun_family = AF_UNIX;
	snprintf(addr->sun_path, sizeof(addr->sun_path) - 1,
		 "/tmp/rr-tracee-ctrlsock-%d", tid);
}

#endif /* SYSCALL_BUFFER_H_ */
