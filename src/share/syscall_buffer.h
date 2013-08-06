/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#ifndef SYSCALL_BUFFER_H_
#define SYSCALL_BUFFER_H_

#ifndef _GNU_SOURCE
# define _GNU_SOURCE 1
#endif

#include <stdint.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

#define SYSCALLBUF_LIB_FILENAME "librr_syscall_buffer.so"
/* This size counts the header along with record data. */
#define SYSCALLBUF_BUFFER_SIZE (1 << 20)

/* "Magic" (rr-implemented) syscall that we use to initialize the
 * syscallbuf. */
#define RRCALL_init_syscall_buffer -42
#define __NR_rrcall_init_syscall_buffer (42 | RRCALL_BIT)
#define SYS_rrcall_init_syscall_buffer __NR_rrcall_init_syscall_buffer

/**
 * True if |_eip| is an $ip within the syscallbuf library.  This *does
 * not* imply that $ip is at a buffered syscall; use the macro below
 * for that.
 */
#define SYSCALLBUF_IS_IP_IN_LIB(_eip, _ctx)				\
	((uintptr_t)(_ctx)->syscallbuf_lib_start <= (uintptr_t)(_eip)	\
	 && (uintptr_t)(_eip) <= (uintptr_t)(_ctx)->syscallbuf_lib_end)

/**
 * True when |_eip| is at a buffered syscall, i.e. one initiated by a
 * libc wrapper in the library.  Callers may assume
 * |SYSCALLBUF_IS_IP_IN_LIB()| is implied by this.
 */
#define SYSCALLBUF_IS_IP_BUFFERED_SYSCALL(_eip, _ctx)			\
	((uintptr_t)(_eip) == (uintptr_t)(_ctx)->untraced_syscall_ip)	\

/**
 * The syscall buffer comprises an array of these variable-length
 * records, along with the header below.
 */
struct syscallbuf_record {
	/* Return value from the syscall.  This can be a memory
	 * address, so must be reserved a full |long|. */
	long ret;
	/* Syscall number.
	 *
	 * NB: the x86 linux ABI has 350 syscalls as of 3.9.6 and
	 * x86-64 defines 313, so this is a pretty safe storage
	 * allocation.  It would be an earth-shattering event if the
	 * syscall surface were doubled in a short period of time, and
	 * even then we would have a comfortable cushion.  Still,
	 *
	 * TODO: static_assert this can hold largest syscall num */
	uint32_t syscallno : 10;
	/* Did the tracee arm/disarm the desched notification for this
	 * syscall? */
	uint32_t desched : 1;
	/* Size of entire record in bytes: this struct plus extra
	 * recorded data stored inline after the last field, not
	 * including padding.
	 *
	 * TODO: static_assert this can repr >= buffer size */
	uint32_t size : 21;
	/* Extra recorded outparam data starts here. */
	unsigned char extra_data[0];
} __attribute__((__packed__));

/**
 * This struct summarizes the state of the syscall buffer.  It happens
 * to be located at the start of the buffer.
 */
struct syscallbuf_hdr {
	/* The number of valid syscallbuf_record bytes in the buffer,
	 * not counting this header. */
	uint32_t num_rec_bytes : 30;
	/* True if the current syscall should not be committed to the
	 * buffer, for whatever reason; likely interrupted by
	 * desched. */
	uint32_t abort_commit : 1;
	/* This tracks whether the buffer is currently in use for a
	 * system call. This is helpful when a signal handler runs
	 * during a wrapped system call; we don't want it to use the
	 * buffer for its system calls. */
	uint32_t locked : 1;

	struct syscallbuf_record recs[0];
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
 * Return a pointer to what may be the next syscall record.
 *
 * THIS POINTER IS NOT GUARANTEED TO BE VALID!!!  Caveat emptor.
 */
inline static struct syscallbuf_record* next_record(struct syscallbuf_hdr* hdr)
{	
	return (void*)hdr->recs + hdr->num_rec_bytes;
}

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

/**
 * Return nonzero if an attempted open() of |filename| should be
 * blocked.
 *
 * The background of this hack is that rr doesn't support DRI/DRM
 * currently, so we use the blunt stick of refusing to open this
 * interface file as a way of disabling it entirely.  (In addition to
 * tickling xorg.conf, which doesn't entirely do the trick.)  It's
 * known how to fix this particular, so let's not let this hack grow
 * too much by piling on.
 */
inline static int is_blacklisted_filename(const char* filename)
{
	return !strcmp("/dev/dri/card0", filename);
}

#endif /* SYSCALL_BUFFER_H_ */
