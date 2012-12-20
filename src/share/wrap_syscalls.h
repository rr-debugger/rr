/*
 * wrap_syscalls.h
 *
 *  Created on: Nov 28, 2012
 *      Author: user
 */

#ifndef WRAP_SYSCALLS_H_
#define WRAP_SYSCALLS_H_

#define WRAP_SYSCALLS_LIB_FILENAME				"libwrap_syscalls.so"

#define WRAP_SYSCALLS_CACHE_SIZE				((1 << 20) - sizeof(int)) /* Accounting for buffer[0] which holds size */
#define WRAP_SYSCALLS_CACHE_FILENAME_PREFIX 	"record_cache_"
#define WRAP_SYSCALLS_RECORD_BASE_SIZE 			(3 * sizeof(int))

#define WRAP_SYSCALLS_FLUSH_EVENT							SYS_gettid
#define WRAP_SYSCALLS_CALLSITE_IN_WRAPPER(eip,context) 		((long)(eip) >= (long)(context->syscall_wrapper_start) && \
															 (long)(eip) <= (long)(context->syscall_wrapper_end))
#endif /* WRAP_SYSCALLS_H_ */
