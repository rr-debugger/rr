/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#ifndef TYPES_H_
#define TYPES_H_

#include <stddef.h>
#include <stdio.h>
#include <stdint.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/user.h>

#include "../external/tree.h"

#define __unused __attribute__((unused))

#define CHECK_ALIGNMENT(addr) 	assert(((long int)(addr) & 0x3) == 0)
#define PAGE_ALIGN(length)		((length + PAGE_SIZE - 1) & PAGE_MASK)

#define PTR_SIZE		(sizeof(void*))
#define INT_SIZE		(sizeof(int))

#define UUL_COLUMN_SIZE 	20
#define LI_COLUMN_SIZE 		11

typedef enum { FALSE = 0, TRUE = 1 } bool;

typedef unsigned char byte;

struct syscallbuf_hdr;

/**
 * A trace_frame is one "trace event" from a complete trace.  During
 * recording, a trace_frame is recorded upon each significant event,
 * for example a context-switch or syscall.  During replay, a
 * trace_frame represents a "next state" that needs to be transitioned
 * into, and the information recorded in the frame dictates the nature
 * of the transition.
 */
struct trace_frame
{
	/* meta information */
	uint32_t global_time;
	uint32_t thread_time;
	pid_t tid;
	int stop_reason;
	int state;

	/* hpc data */
	uint64_t hw_interrupts;
	uint64_t page_faults;
	uint64_t rbc;
	uint64_t insts;

	/* register values */
	struct user_regs_struct recorded_regs;
};


struct context {
	struct trace_frame trace;
	struct hpc_context* hpc;

	/* recorder */
	int exec_state;
	int event;
	int allow_ctx_switch;
	/* Nonzero when this context has been interrupted by a desched
	 * event while making a buffered may-block syscall (and
	 * remained blocked in the syscall).  When this is the case,
	 * we have to allow switching out this context to make
	 * progress, in general.  We also need to record some extra
	 * trace data to ensure replay doesn't diverge. */
	int desched;
	/* Nonzero after the trace recorder has flushed the
	 * syscallbuf.  When this happens, the recorder must prepare a
	 * "reset" of the buffer, to zero the record count, at the
	 * next available slow (taking |desched| into
	 * consideration). */
	int flushed_syscallbuf;
	void *scratch_ptr;
	int scratch_size;
	int switch_counter;
	int last_syscall;

	void *recorded_scratch_ptr_0;
	void *recorded_scratch_ptr_1;

	int recorded_scratch_size;

	/* The child's desched counter event fd number, and our local
	 * dup. */
	int desched_fd, desched_fd_child;

	/* shared */
	struct user_regs_struct child_regs;
	FILE *inst_dump;
	/* This is always the "real" tid of the tracee. */
	pid_t child_tid;
	/* This is always the recorded tid of the tracee.  During
	 * recording, it's synonymous with child_tid, and during
	 * replay it's the tid that was recorded. */
	pid_t rec_tid;
	int child_mem_fd;
	int child_sig;
	int status;

	/* The instruction pointer from which untraced syscalls will
	 * originate, used to determine whether a syscall is being
	 * made by the syscallbuf wrappers or not. */
	void* untraced_syscall_ip;
	/* Start and end of the mapping of the syscallbuf code
	 * section, used to determine whether a tracee's $ip is in the
	 * lib. */
	void* syscallbuf_lib_start;
	void* syscallbuf_lib_end;
	/* Points at rr's mapping of the (shared) syscall buffer
	 * itself. */
	struct syscallbuf_hdr* syscallbuf_hdr;
	/* Points at the tracee's mapping of the buffer. */
	void* syscallbuf_child;

	RB_ENTRY(context) entry;
};

struct mmapped_file {
	int time; // mmap time
	int tid;

	char filename[1024];
	struct stat stat;

	// mmap region
	void* start;
	void* end;
};

/**
 * command line arguments for rr
 */

#define INVALID			0
#define RECORD			1
#define REPLAY			2

#define DUMP_ON_NONE 	-1001
#define DUMP_ON_ALL 	1000

#define DUMP_AT_NONE 	-1

#define CHECKSUM_NONE			-3
#define CHECKSUM_SYSCALL		-2
#define CHECKSUM_ALL			-1

struct flags {
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
};

#endif /* TYPES_H_ */
