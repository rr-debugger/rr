/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#ifndef RR_SYSCALL_BUFFER_H_
#define RR_SYSCALL_BUFFER_H_

#ifdef __cplusplus
extern "C" {
#endif

#ifndef _GNU_SOURCE
# define _GNU_SOURCE 1
#endif

#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

/* This is pretty arbitrary; SIGSYS is unused by linux, and hopefully
 * normal applications don't use it either. */
#define SYSCALLBUF_DESCHED_SIGNAL SIGSYS

#define SYSCALLBUF_LIB_FILENAME "librrpreload.so"
/* This size counts the header along with record data. */
#define SYSCALLBUF_BUFFER_SIZE (1 << 20)

/* Set this env var to enable syscall buffering. */
#define SYSCALLBUF_ENABLED_ENV_VAR "_RR_USE_SYSCALLBUF"

/* "Magic" (rr-implemented) syscall that we use to initialize the
 * syscallbuf.
 *
 * NB: magic syscalls must be positive, because with at least linux
 * 3.8.0 / eglibc 2.17, rr only gets a trap for the *entry* of invalid
 * syscalls, not the exit.  rr can't handle that yet. */
/* TODO: static_assert(LAST_SYSCALL < FIRST_RRCALL) */
#define FIRST_RRCALL 400

#define __NR_rrcall_init_buffers 442
#define __NR_rrcall_monkeypatch_vdso 443
#define SYS_rrcall_init_buffers __NR_rrcall_init_buffers
#define SYS_rrcall_monkeypatch_vdso __NR_rrcall_monkeypatch_vdso

typedef unsigned char byte;

/**
 * Packs up the inout parameters passed to |rrcall_init_buffers()|.
 * We use this struct because there are too many params to pass
 * through registers on at least x86.  (It's also a little cleaner.)
 */
struct rrcall_init_buffers_params {
	/* "In" params. */
	/* The syscallbuf lib's idea of whether buffering is enabled.
	 * We let the syscallbuf code decide in order to more simply
	 * replay the same decision that was recorded. */
	int syscallbuf_enabled;
	/* Where our traced syscalls will originate. */
	void* traced_syscall_ip;
	/* Where our untraced syscalls will originate. */
	void* untraced_syscall_ip;
	/* Address of the control socket the child expects to connect
	 * to. */
	struct sockaddr_un* sockaddr;
	/* Pre-prepared IPC that can be used to share fds; |fdptr| is
	 * a pointer to the control-message data buffer where the fd
	 * number being shared will be stored. */
	struct msghdr* msg;
	int* fdptr;
	/* Preallocated space the tracer can use to make socketcall
	 * syscalls. */
	struct socketcall_args* args_vec;

	/* "Out" params. */
	/* Returned pointer to and size of the shared syscallbuf
	 * segment. */
	void* syscallbuf_ptr;
};

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
	byte extra_data[0];
} __attribute__((__packed__));

/**
 * This struct summarizes the state of the syscall buffer.  It happens
 * to be located at the start of the buffer.
 */
struct syscallbuf_hdr {
	/* The number of valid syscallbuf_record bytes in the buffer,
	 * not counting this header. */
	uint32_t num_rec_bytes : 29;
	/* True if the current syscall should not be committed to the
	 * buffer, for whatever reason; likely interrupted by
	 * desched. */
	uint32_t abort_commit : 1;
	/* This tracks whether the buffer is currently in use for a
	 * system call. This is helpful when a signal handler runs
	 * during a wrapped system call; we don't want it to use the
	 * buffer for its system calls. */
	uint32_t locked : 1;
	/* Nonzero when rr needs to worry about the desched signal.
	 * When it's zero, the desched signal can safely be
	 * discarded. */
	uint32_t desched_signal_may_be_relevant : 1;

	struct syscallbuf_record recs[0];
} __attribute__((__packed__));
/* TODO: static_assert(sizeof(uint32_t) ==
 *                     sizeof(struct syscallbuf_hdr)) */

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
	uintptr_t next = (uintptr_t)hdr->recs + hdr->num_rec_bytes;
	return (struct syscallbuf_record*)next;
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
	return (!strcmp("/dev/dri/card0", filename)
		|| !strcmp("/dev/nvidiactl", filename)
		|| !strcmp("/usr/share/alsa/alsa.conf", filename));
}

#ifdef __cplusplus
}
#endif

#endif /* RR_SYSCALL_BUFFER_H_ */
