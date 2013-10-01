/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#ifndef TYPES_H_
#define TYPES_H_

#include <stddef.h>
#include <stdio.h>
#include <stdint.h>

#include <sys/stat.h>
#include <sys/types.h>

#define __unused __attribute__((unused))

#define CHECK_ALIGNMENT(addr) 	assert(((long int)(addr) & 0x3) == 0)
#define PAGE_ALIGN(length)		((length + PAGE_SIZE - 1) & PAGE_MASK)

#define PTR_SIZE		(sizeof(void*))
#define INT_SIZE		(sizeof(int))

#define UUL_COLUMN_SIZE 	20
#define LI_COLUMN_SIZE 		11

typedef enum { FALSE = 0, TRUE = 1 } bool;

typedef unsigned char byte;

/**
 * command line arguments for rr
 */

#define INVALID			0
#define RECORD			1
#define REPLAY			2

#define DUMP_ON_ALL 	10000
#define DUMP_ON_NONE 	-DUMP_ON_ALL

#define DUMP_AT_NONE 	-1

#define CHECKSUM_NONE			-3
#define CHECKSUM_SYSCALL		-2
#define CHECKSUM_ALL			-1

struct flags {
	/* Max counter value before the scheduler interrupts a tracee. */
	int max_rbc;
	/* Max number of trace events before the scheduler
	 * de-schedules a tracee. */
	int max_events;
	/* Whenever |ignore_sig| is pending for a tracee, decline to
	 * deliver it. */
	int ignore_sig;
	int option;
	bool redirect;
	bool use_syscall_buffer;
	char *syscall_buffer_lib_path;
	int dump_on;	// event
	int dump_at;	// global time
	int checksum;
	/* Nonzero when we're replaying without a controlling debugger. */
	int autopilot;
	/* IP port to listen on for debug connections. */
	int dbgport;
	/* Number of seconds to wait after startup, before starting
	 * "real work". */
	int wait_secs;
	/* Nonzero when not-absolutely-urgently-critical messages will
	 * be logged. */
	int verbose;
};

struct msghdr;
/**
 * These arguments are pushed on the stack for the recvmsg socketcall.
 */
struct recvmsg_args {
	int fd;
	struct msghdr* msg;
};

#endif /* TYPES_H_ */
