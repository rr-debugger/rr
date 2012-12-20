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
#define WRAP_SYSCALLS_RECORD_BASE_SIZE 			(3) /* Base size in integers */

/* Wrapped syscalls need to be added here. Note: be careful of syscalls that originate from wrapper internal code */
#define WRAP_SYSCALLS_CALLSITE_IN_WRAPPER(eip,context) 		( ((long)(eip) >= (long)(context->syscall_wrapper_start)  && \
															   (long)(eip) <= (long)(context->syscall_wrapper_end)  ) && \
															  (context->event == SYS_clock_gettime 					  || \
															   context->event == SYS_gettimeofday 					  || \
															   context->event == SYS_write		 					  || \
															   context->event == SYS_read		 					  || \
															   context->event == SYS_fstat64						  || \
															   context->event == SYS_lstat64		 				  || \
															   context->event == SYS_stat64		 					  || \
															   context->event == SYS_epoll_wait 					  || \
															   context->event == SYS_socketcall	 					  || \
															   context->event == SYS_futex							)	 )

#endif /* WRAP_SYSCALLS_H_ */
