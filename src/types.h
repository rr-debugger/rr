/* -*- Mode: C++; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#ifndef RR_TYPES_H_
#define RR_TYPES_H_

#include <linux/limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>

#include <sys/stat.h>
#include <sys/types.h>

#include <string>

#define CHECK_ALIGNMENT(addr) 	assert(((long int)(addr) & 0x3) == 0)

#define PTR_SIZE		(sizeof(void*))
#define INT_SIZE		(sizeof(int))

#define UUL_COLUMN_SIZE 	20
#define LI_COLUMN_SIZE 		11

typedef unsigned char byte;

/**
 * command line arguments for rr
 */

#define INVALID			0
#define RECORD			1
#define REPLAY			2
#define DUMP_EVENTS		3

#define DUMP_ON_ALL 	10000
#define DUMP_ON_NONE 	-DUMP_ON_ALL

#define DUMP_AT_NONE 	-1

#define CHECKSUM_NONE			-3
#define CHECKSUM_SYSCALL		-2
#define CHECKSUM_ALL			-1

// We let users specify which process should be "created" before
// starting a debug session for it.  Problem is, "process" in this
// context is ambiguous.  It could mean the "thread group", which is
// created at fork().  Or it could mean the "address space", which is
// created at exec() (after the fork).
//
// We force choosers to specify which they mean, and default to the
// much more useful (and probably common) exec() definition.
enum { CREATED_DEFAULT = 0, CREATED_EXEC, CREATED_FORK };

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
	std::string syscall_buffer_lib_path;
	int dump_on;	// event
	int dump_at;	// global time
	int checksum;
	/* IP port to listen on for debug connections. */
	int dbgport;
	/* Number of seconds to wait after startup, before starting
	 * "real work". */
	int wait_secs;
	/* True when not-absolutely-urgently-critical messages will be
	 * logged. */
	bool verbose;
	/* True when tracee processes in record and replay are allowed
	 * to run on any logical CPU. */
	bool cpu_unbound;
	/* Always allow emergency debugging. */
	bool force_enable_debugger;
	/* Mark the trace global time along with tracee writes to
	 * stdio. */
	bool mark_stdio;
	// Check that cached mmaps match /proc/maps after each event.
	bool check_cached_mmaps;
	bool suppress_warnings;
	// Start a debug server for the task scheduled at the first
	// event at which reached this event AND target_process has
	// been "created".
	uint32_t goto_event;
	pid_t target_process;
	int process_created_how;
	// Dump trace frames in a more easily machine-parseable
	// format.
	bool raw_dump;
	// Only open a debug socket, don't launch the debugger too.
	bool dont_launch_debugger;
	// Pass this file name to debugger with -x
	std::string gdb_command_file_path;

	flags()
	  : max_rbc(0)
	  , max_events(0)
	  , ignore_sig(0)
	  , option(0)
	  , redirect(false)
	  , use_syscall_buffer(false)
	  , syscall_buffer_lib_path("")
	  , dump_on(0)
	  , dump_at(0)
	  , checksum(0)
	  , dbgport(0)
	  , wait_secs(0)
	  , verbose(false)
	  , cpu_unbound(false)
	  , force_enable_debugger(false)
	  , mark_stdio(false)
	  , check_cached_mmaps(false)
	  , goto_event(0)
	  , target_process(0)
	  , process_created_how(0)
	  , raw_dump(false)
	  , dont_launch_debugger(false)
	  , gdb_command_file_path("")
	{}
};

/** Params packaged up for old mmap syscall. */
struct mmap_arg_struct {
	unsigned long addr;
	unsigned long len;
	unsigned long prot;
	unsigned long flags;
        unsigned long fd;
	unsigned long offset;
};

struct msghdr;
/**
 * These arguments are pushed on the stack for the recvmsg socketcall.
 */
struct recvmsg_args {
	long fd;
	struct msghdr* msg;
	long flags;
};

#endif /* RR_TYPES_H_ */
