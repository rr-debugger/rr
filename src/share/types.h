/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#ifndef TYPES_H_
#define TYPES_H_

#include <stdio.h>
#include <stdint.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/user.h>

#define CHECK_ALIGNMENT(addr) 	assert(((long int)(addr) & 0x3) == 0)
#define PAGE_ALIGN(length)		((length + PAGE_SIZE - 1) & PAGE_MASK)

#define PTR_SIZE		(sizeof(void*))
#define INT_SIZE		(sizeof(int))

#define UUL_COLUMN_SIZE 	20
#define LI_COLUMN_SIZE 		11

#define size_t int

typedef enum { FALSE = 0, TRUE = 1 } bool;

struct trace
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
	pid_t rec_tid; /* thread id recording thread */

	struct trace trace;
	struct hpc_context* hpc;

	/* recorder */
	int exec_state;
	int event;
	int allow_ctx_switch;
	void *scratch_ptr;
	int scratch_size;
	int switch_counter;
	int last_syscall;

	void *recorded_scratch_ptr_0;
	void *recorded_scratch_ptr_1;

	int recorded_scratch_size;

	void * syscall_wrapper_start;
	void * syscall_wrapper_end;
	int * syscall_wrapper_cache;
	int * syscall_wrapper_cache_child; // address of the cache buffer in the child

	/* shared */
	struct user_regs_struct child_regs;
	FILE *inst_dump;
	pid_t child_tid;
	int child_mem_fd;
	int child_sig;
	int replay_sig;
	int status;


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
	char *filter_lib_path;
	int dump_on;	// event
	int dump_at;	// global time
	int checksum;
	/* Nonzero when we're replaying without a controlling debugger. */
	int autopilot;
};

#endif /* TYPES_H_ */
