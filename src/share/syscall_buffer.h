/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

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
#define SYSCALL_BUFFER_RECORD_BASE_SIZE 			(3) /* Base size in integers */

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

#endif /* SYSCALL_BUFFER_H_ */
