/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#define _GNU_SOURCE

//#define DEBUGTAG "Util"

//#define FIRST_INTERESTING_EVENT 10700
//#define LAST_INTERESTING_EVENT 10900

#include "util.h"

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <libdis.h>
#include <limits.h>
#include <linux/magic.h>
#include <linux/net.h>
#include <linux/perf_event.h>
#include <malloc.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "../recorder/rec_sched.h"
#include "../replayer/replayer.h"

#include "dbg.h"
#include "ipc.h"
#include "sys.h"
#include "syscall_buffer.h"
#include "task.h"
#include "trace.h"
#include "types.h"

#ifndef PTRACE_EVENT_SECCOMP
#define PTRACE_O_TRACESECCOMP			0x00000080
#define PTRACE_EVENT_SECCOMP_OBSOLETE	8 // ubuntu 12.04
#define PTRACE_EVENT_SECCOMP			7 // ubuntu 12.10 and future kernels
#endif

/* The tracee doesn't open the desched event fd during replay, so it
 * can't be shared to this process.  We pretend that the tracee shared
 * this magic fd number with us and then give it a free pass for fd
 * checks that include this fd. */
#define REPLAY_DESCHED_EVENT_FD -123
#define NUM_MAX_MAPS 1024

/* The syscallbuf shared with tracees is created with this prefix
 * followed by the tracee tid, then immediately unlinked and shared
 * anonymously. */
#define SYSCALLBUF_SHMEM_FILENAME_PREFIX "/dev/shm/rr-tracee-shmem-"

struct flags flags = { 0 };

static void* scratch_table[MAX_TID] = {NULL} ;
static size_t scratch_table_size = 0;
static size_t scratch_overall_size = 0;

static struct sigaction * sig_handler_table[MAX_TID][_NSIG] = { {NULL} };

static size_t num_shared_maps = 0;
static void* shared_maps_starts[MAX_TID] = {0};
static void* shared_maps_ends[MAX_TID] = {0};

const struct flags* rr_flags(void)
{
	return &flags;
}

struct flags* rr_flags_for_init(void)
{
	static int initialized;
	if (!initialized) {
		initialized = 1;
		return &flags;
	}
	fatal("Multiple initialization of flags.");
	return NULL;		/* not reached */
}

static void* get_mmaped_region_end(struct task* t, void* start)
{
	struct mapped_segment_info info;
	int found_info = find_segment_containing(t, start, &info);
	assert_exec(t, found_info, "Didn't find segment containing %p", start);
	return info.end_addr;
}

void add_protected_map(struct task *t, void *start){
	assert(num_shared_maps < NUM_MAX_MAPS);
	shared_maps_starts[num_shared_maps] = start;
	shared_maps_ends[num_shared_maps++] = get_mmaped_region_end(t,start);
}

bool is_protected_map(struct task *t, void *start){
	int i;
	for (i = 0 ; i < num_shared_maps; ++i) {
		if (shared_maps_starts[i] <= start && start <  shared_maps_ends[i]) {
			return TRUE;
		}
	}
	return FALSE;
}

static int is_start_of_scratch_region(void* start_addr)
{
	int i;
	for (i = 0 ; i < scratch_table_size; ++i) {
		if (scratch_table[i] == start_addr) {
			return 1;
		}
	}
	return 0;
}

double now_sec(void)
{
	struct timespec tp;
	clock_gettime(CLOCK_MONOTONIC, &tp);
	return (double)tp.tv_sec + (double)tp.tv_nsec / 1e9;
}

int nanosleep_nointr(const struct timespec* ts)
{
	struct timespec req = *ts;
	while (1) {
		struct timespec rem;
		int err = nanosleep(&req, &rem);
		if (0 == err || EINTR != errno) {
			return err;
		}
		req = rem;
	}
}

int probably_not_interactive(void)
{
	/* Eminently tunable heuristic, but this is guaranteed to be
	 * true during rr unit tests, where we care most about this
	 * check (to a first degree).  A failing test shouldn't
	 * hang. */
	return !isatty(STDERR_FILENO);
}

int is_ptrace_seccomp_event(int event)
{
	return (PTRACE_EVENT_SECCOMP_OBSOLETE == event ||
		PTRACE_EVENT_SECCOMP == event);
}

const char* ptrace_event_name(int event)
{
	switch (event) {
#define CASE(_id) case PTRACE_EVENT_## _id: return #_id
	CASE(FORK);
	CASE(VFORK);
	CASE(CLONE);
	CASE(EXEC);
	CASE(VFORK_DONE);
	CASE(EXIT);
	/* XXX Ubuntu 12.04 defines a "PTRACE_EVENT_STOP", but that
	 * has the same value as the newer EVENT_SECCOMP, so we'll
	 * ignore STOP. */
#ifdef PTRACE_EVENT_SECCOMP_OBSOLETE
	CASE(SECCOMP_OBSOLETE);
#else
	CASE(SECCOMP);
#endif
	default:
		return "???EVENT";
#undef CASE
	}
}

const char* signalname(int sig)
{
	/* strsignal() would be nice to use here, but it provides TMI. */
	if (SIGRTMIN <= sig && sig <= SIGRTMAX) {
		static __thread char buf[] = "SIGRT00000000";
		snprintf(buf, sizeof(buf) - 1, "SIGRT%d", sig - SIGRTMIN);
		return buf;
	}

	switch (sig) {
#define CASE(_id) case _id: return #_id
	CASE(SIGHUP); CASE(SIGINT); CASE(SIGQUIT); CASE(SIGILL);
	CASE(SIGTRAP); CASE(SIGABRT); /*CASE(SIGIOT);*/ CASE(SIGBUS);
	CASE(SIGFPE); CASE(SIGKILL); CASE(SIGUSR1); CASE(SIGSEGV);
	CASE(SIGUSR2); CASE(SIGPIPE); CASE(SIGALRM); CASE(SIGTERM);
	CASE(SIGSTKFLT); /*CASE(SIGCLD);*/ CASE(SIGCHLD); CASE(SIGCONT);
	CASE(SIGSTOP); CASE(SIGTSTP); CASE(SIGTTIN); CASE(SIGTTOU);
	CASE(SIGURG); CASE(SIGXCPU); CASE(SIGXFSZ); CASE(SIGVTALRM);
	CASE(SIGPROF); CASE(SIGWINCH); /*CASE(SIGPOLL);*/ CASE(SIGIO);
	CASE(SIGPWR); CASE(SIGSYS);
#undef CASE

	default:
		return "???signal";
	}
}

const char* syscallname(int syscall)
{
	switch (syscall) {
#define SYSCALL_DEF(_, _name, __) case __NR_## _name: return #_name;
#include "../replayer/syscall_defs.h"
#undef SYSCALL_DEF

	case SYS_restart_syscall:
		return "restart_syscall";
	default:
		return "???syscall";
	}
}

int signal_pending(int status)
{
	int sig = WSTOPSIG(status);

	if (status == 0) {
		return 0;
	}
	assert(WIFSTOPPED(status));

	switch (sig) {
	case (SIGTRAP | 0x80):
		/* We ask for PTRACE_O_TRACESYSGOOD, so this was a
		 * trap for a syscall.  Pretend like it wasn't a
		 * signal. */
		return 0;
	case SIGTRAP:
		/* For a "normal" SIGTRAP, it's a ptrace trap if
		 * there's a ptrace event.  If so, pretend like we
		 * didn't get a signal.  Otherwise it was a genuine
		 * TRAP signal raised by something else (most likely a
		 * debugger breakpoint). */
		return GET_PTRACE_EVENT(status) ? 0 : SIGTRAP;
	default:
		/* XXX do we really get the high bit set on some
		 * SEGVs? */
		return sig & ~0x80;
	}
}

void detach_and_reap(struct task* t)
{
	sys_ptrace_detach(t->tid);
	if (t->unstable) {
		log_warn("%d is unstable; not blocking on its termination",
			 t->tid);
		goto sleep_hack;
	}

	debug("Joining with exiting %d ...", t->tid);
	while (1) {
		int err = waitpid(t->tid, &t->status, __WALL);
		if (-1 == err && ECHILD == errno) {
			debug(" ... ECHILD");
			break;
		} else if (-1 == err) {
			assert_exec(t, EINTR == errno,
				    "waitpid(%d) returned -1, errno %d",
				    t->tid, errno);
		}
		if (err == t->tid && (WIFEXITED(t->status) || 
				      WIFSIGNALED(t->status))) {
			debug(" ... exited with status 0x%x", t->status);
			break;
		} else if (err == t->tid) {
			assert_exec(t, (PTRACE_EVENT_EXIT ==
					GET_PTRACE_EVENT(t->status)),
				    "waitpid(%d) return status %d",
				    t->tid, t->status);
		}
	}

sleep_hack:
	/* clone()'d tasks can have a pid_t* |ctid| argument that's
	 * written with the new task's pid.  That pointer can also be
	 * used as a futex: when the task dies, the original ctid
	 * value is cleared and a FUTEX_WAKE is done on the
	 * address. So pthread_join() is basically a standard futex
	 * wait loop.
	 *
	 * That means that the kernel writes shared memory behind rr's
	 * back, which can diverge replay.  The "real fix" for this is
	 * for rr to track access to shared memory, like the |ctid|
	 * location.  But until then, we (attempt to) let "time"
	 * resolve this memory race with the sleep() hack below. */
	{
		/* Why 4ms?  Because
		 *
		 * $ for i in $(seq 10); do (cd $rr/src/test/ && bash thread_cleanup.run) & done
		 *
		 * has been observed to fail when we sleep 3ms, but
		 * not when we sleep 4ms.  Yep, this hack is that
		 * horrible! */
		struct timespec ts = { .tv_nsec = 4000000LL };
		nanosleep_nointr(&ts);
	}
}

void print_register_file_tid(pid_t tid)
{
	struct user_regs_struct regs;
	read_child_registers(tid, &regs);
	print_register_file(&regs);
}

void print_register_file(struct user_regs_struct* regs)
{
	fprintf(stderr, "Printing register file:\n");
	fprintf(stderr, "eax: %lx\n", regs->eax);
	fprintf(stderr, "ebx: %lx\n", regs->ebx);
	fprintf(stderr, "ecx: %lx\n", regs->ecx);
	fprintf(stderr, "edx: %lx\n", regs->edx);
	fprintf(stderr, "esi: %lx\n", regs->esi);
	fprintf(stderr, "edi: %lx\n", regs->edi);
	fprintf(stderr, "ebp: %lx\n", regs->ebp);
	fprintf(stderr, "esp: %lx\n", regs->esp);
	fprintf(stderr, "eip: %lx\n", regs->eip);
	fprintf(stderr, "eflags %lx\n",regs->eflags);
	fprintf(stderr, "orig_eax %lx\n", regs->orig_eax);
	fprintf(stderr, "xcs: %lx\n", regs->xcs);
	fprintf(stderr, "xds: %lx\n", regs->xds);
	fprintf(stderr, "xes: %lx\n", regs->xes);
	fprintf(stderr, "xfs: %lx\n", regs->xfs);
	fprintf(stderr, "xgs: %lx\n", regs->xgs);
	fprintf(stderr, "xss: %lx\n", regs->xss);
	fprintf(stderr, "\n");

}

/**
 * Remove leading blank characters from |str| in-place.  |str| must be
 * a valid string.
 */
static void trim_leading_blanks(char* str)
{
	char* trimmed = str;
	while (isblank(*trimmed)) ++trimmed;
	memmove(str, trimmed, strlen(trimmed) + 1/*\0 byte*/);
}

/**
 * The following helpers are used to iterate over a tracee's memory
 * maps.  Clients call |iterate_memory_map()|, passing an iterator
 * function that's invoked for each mapping until either the iterator
 * stops iteration by not returning CONTINUE_ITERATING, or until the
 * last mapping has been iterated over.
 *
 * For each map, a |struct map_iterator_data| object is provided which
 * contains segment info, the size of the mapping, and the raw
 * /proc/maps line the data was parsed from.
 *
 * Additionally, if clients pass the ITERATE_READ_MEMORY flag, the
 * contents of each segment are read and passed through the |mem|
 * field in the |struct map_iterator_data|.
 *
 * Any pointers passed transitively to the iterator function are
 * *owned by |iterate_memory_map()||*.  Iterator functions must copy
 * the data they wish to save beyond the scope of the iterator
 * function invocation.
 */
enum { CONTINUE_ITERATING, STOP_ITERATING };
struct map_iterator_data {
	struct mapped_segment_info info;
	/* The nominal size of the data segment. */
	ssize_t size_bytes;
	/* Pointer to data read from the segment if requested,
	 * otherwise NULL. */
	void* mem;
	/* Length of data read from segment.  May be less than nominal
	 * segment length if an error occurs. */
	ssize_t mem_len;
	const char* raw_map_line;
};
typedef int (*memory_map_iterator_t)(void* it_data, struct task* t,
				     const struct map_iterator_data* data);

typedef int (*read_segment_filter_t)(void* filt_data, struct task* t,
				     const struct mapped_segment_info* info);
static const read_segment_filter_t kNeverReadSegment = (void*)0;
static const read_segment_filter_t kAlwaysReadSegment = (void*)1;

static int caller_wants_segment_read(struct task* t,
				     const struct mapped_segment_info* info,
				     read_segment_filter_t filt,
				     void* filt_data)
{
	if (kNeverReadSegment == filt) {
		return 0;
	}
	if (kAlwaysReadSegment == filt) {
		return 1;
	}
	return filt(filt_data, t, info);
}

static void iterate_memory_map(struct task* t,
			       memory_map_iterator_t it, void* it_data,
			       read_segment_filter_t filt, void* filt_data)
{
	FILE* maps_file;
	char line[PATH_MAX];
	{
		char maps_path[PATH_MAX];
		snprintf(maps_path, sizeof(maps_path) - 1, "/proc/%d/maps",
			t->tid);
		assert_exec(t, (maps_file = fopen(maps_path, "r")),
			    "Failed to open %s", maps_path);
	}
	while (fgets(line, sizeof(line), maps_file)) {
		struct map_iterator_data data;
		char flags[32];
		int nparsed;
		int next_action;

		memset(&data, 0, sizeof(data));
		data.raw_map_line = line;

		nparsed = sscanf(line, "%p-%p %31s %Lx %x:%x %Lu %s",
				 &data.info.start_addr, &data.info.end_addr,
				 flags, &data.info.file_offset,
				 &data.info.dev_major, &data.info.dev_minor,
				 &data.info.inode, data.info.name);
		trim_leading_blanks(data.info.name);

		assert_exec(t,
			    (8/*number of info fields*/ == nparsed
			     || 7/*num fields if name is blank*/ == nparsed),
			    "Only parsed %d fields of segment info from\n"
			    "%s",
			    nparsed, data.raw_map_line);

		data.info.prot |= strchr(flags, 'r') ? PROT_READ : 0;
		data.info.prot |= strchr(flags, 'w') ? PROT_WRITE : 0;
		data.info.prot |= strchr(flags, 'x') ? PROT_EXEC : 0;
		data.info.flags |= strchr(flags, 'p') ? MAP_PRIVATE : 0;
		data.info.flags |= strchr(flags, 's') ? MAP_SHARED : 0;
		data.size_bytes = ((intptr_t)data.info.end_addr -
				   (intptr_t)data.info.start_addr);
		if (caller_wants_segment_read(t, &data.info,
					      filt, filt_data)) {
			data.mem =
				read_child_data_checked(t, data.size_bytes,
							data.info.start_addr,
							&data.mem_len);
			/* TODO: expose read errors, somehow. */
			data.mem_len = MAX(0, data.mem_len);
		}

		next_action = it(it_data, t, &data);
		sys_free(&data.mem);

		if (STOP_ITERATING == next_action) {
			break;
		}
	}
	fclose(maps_file);
}

static int print_process_mmap_iterator(void* unused, struct task* t,
				       const struct map_iterator_data* data)
{
	fputs(data->raw_map_line, stdout);
	return CONTINUE_ITERATING;
}

void print_process_mmap(struct task* t)
{
	return iterate_memory_map(t, print_process_mmap_iterator, NULL,
				  kNeverReadSegment, NULL);
}

/**
 * Return nonzero if |addr| falls within |info|'s segment.
 */
static int addr_in_segment(void* addr, const struct mapped_segment_info* info)
{
	return info->start_addr <= addr && addr < info->end_addr;
}

static int find_segment_iterator(void* it_data, struct task* t,
				 const struct map_iterator_data* data)
{
	struct mapped_segment_info* info = it_data;
	void* search_addr = info->start_addr;
	if (addr_in_segment(search_addr, &data->info)) {
		memcpy(info, &data->info, sizeof(*info));
		return STOP_ITERATING;
	}
	return CONTINUE_ITERATING;
}

int find_segment_containing(struct task* t, void* search_addr,
			    struct mapped_segment_info* info)
{
	memset(info, 0, sizeof(*info));
	info->start_addr = search_addr;
	iterate_memory_map(t, find_segment_iterator, info,
			   kNeverReadSegment, NULL);
	return addr_in_segment(search_addr, info);
}

char* get_inst(struct task* t, int eip_offset, int* opcode_size)
{
	pid_t tid = t->tid;
	char* buf = NULL;
	unsigned long eip = read_child_eip(tid);
	ssize_t nr_read_bytes;
	unsigned char* inst = read_child_data_checked(t, 128, (void*)(eip + eip_offset), &nr_read_bytes);

	if (nr_read_bytes <= 0) {
		sys_free((void**)&inst);
		return NULL;
	}

	x86_init(opt_none, 0, 0);

	x86_insn_t x86_inst;
	unsigned int size = x86_disasm(inst, 128, 0, 0, &x86_inst);
	*opcode_size = size;

	buf = sys_malloc(128);
	if (size) {
		x86_format_insn(&x86_inst, buf, 128, att_syntax);
	} else {
		/* libdiasm does not support the entire instruction set -- pretty sad */
		strcpy(buf, "unknown");
	}
	sys_free((void**) &inst);
	x86_oplist_free(&x86_inst);
	x86_cleanup();

	return buf;
}

bool is_write_mem_instruction(pid_t tid, int eip_offset, int* opcode_size)
{
	unsigned long eip = read_child_eip(tid);
	unsigned char* inst = read_child_data_tid(tid, 128, (void*)(eip + eip_offset));

	x86_init(opt_none, 0, 0);
	x86_insn_t x86_inst;
	unsigned int size = x86_disasm(inst, 128, 0, 0, &x86_inst);
	*opcode_size = size;
	bool retval = (x86_inst.operands->op.access == op_write && x86_inst.operands->op.type > op_immediate);
	x86_oplist_free(&x86_inst);
	x86_cleanup();
	sys_free((void**) &inst);

	return retval;
}


void emulate_child_inst(struct task * t, int eip_offset)
{
	pid_t tid = t->tid;
	struct user_regs_struct regs;
	read_child_registers(tid,&regs);
	unsigned long eip = read_child_eip(tid);
	unsigned char* inst = read_child_data_tid(tid, 128, (void*)(eip + eip_offset));

	x86_init(opt_none, 0, 0);
	x86_insn_t x86_inst;
	unsigned int size = x86_disasm(inst, 128, 0, 0, &x86_inst);

	char buf[128];
	if (size) {
		x86_format_insn(&x86_inst, buf, 128, att_syntax);
	} else {
		/* libdiasm does not support the entire instruction set -- pretty sad */
		strcpy(buf, "unknown");
	}

	if (strcmp("cmpb\t$0x01, (%eax)",buf) == 0) { // emulate the instruction
		unsigned char right_op = (unsigned char)read_child_data_word(tid,(void*)regs.eax);
		union {
			struct {
				unsigned int CF:1;
				unsigned int R1_1:1;
				unsigned int PF:1;
				unsigned int R0_1:1;
				unsigned int AF:1;
				unsigned int R0_2:1;
				unsigned int ZF:1;
				unsigned int SF:1;
				unsigned int TF:1;
				unsigned int IF:1;
				unsigned int DF:1;
				unsigned int OF:1;
			} b ;
			long int l;
		} flags0, flags;
		asm (
		    "cmpb $0x1,%1;" // execute the instruction
		    "pushf;" // store flags (16 bits)
		    "pop %0;" // pop to flags variable
		    : "=r" (flags)
		    : "r" (right_op)
		    :
		);
		assert(flags.b.R1_1 == 1 && flags.b.R0_1 == 0 && flags.b.R0_2 == 0); // sanity check

		flags0.l = regs.eflags;
		flags0.b.CF = flags.b.CF;
		flags0.b.PF = flags.b.PF;
		flags0.b.AF = flags.b.AF;
		flags0.b.ZF = flags.b.ZF;
		flags0.b.SF = flags.b.SF;
		flags0.b.OF = flags.b.OF;
		regs.eflags = flags0.l;
		regs.eip += size; // move past the instruction

		push_pseudosig(t, ESIG_SEGV_MMAP_READ, HAS_EXEC_INFO);
		record_child_data(t, sizeof(long), (void*)regs.eax);
		//record_parent_data(t,SIG_SEGV_MMAP_READ,sizeof(long),regs.eax, &right_op);
		record_event(t);
		pop_pseudosig(t);

		write_child_registers(tid,&regs);
	} else {
		log_err("instruction (%s) emulation not supported yet.",inst);
		assert(0);
	}

	x86_oplist_free(&x86_inst);
	x86_cleanup();
}

void mprotect_child_region(struct task* t, void* addr, int prot)
{
	struct current_state_buffer state;
	size_t length;
	long ret;

	/* Page-align the address. */
	addr = (void*)((int)addr & PAGE_MASK);
	length = get_mmaped_region_end(t, addr) - addr;

	prepare_remote_syscalls(t, &state);
	ret = remote_syscall3(t, &state, SYS_mprotect, addr, length, prot);
	assert(ret == 0);
	finish_remote_syscalls(t, &state);
}

void print_inst(struct task* t)
{
	int size;
	char* str = get_inst(t, 0, &size);
	printf("inst: %s\n", str);
	free(str);
}

void print_process_state(pid_t tid)
{
	char path[64];
	FILE* file;
	printf("child tid: %d\n", tid);
	fflush(stdout);
	bzero(path, 64);
	sprintf(path, "/proc/%d/status", tid);
	if ((file = fopen(path, "r")) == NULL) {
		perror("error reading child memory status\n");
	}

	int c = getc(file);
	while (c != EOF) {
		putchar(c);
		c = getc(file);
	}
	sys_fclose(file);
}


void print_cwd(pid_t tid, char *str)
{
	char path[64];
	fflush(stdout);
	bzero(path, 64);
	sprintf(path, "/proc/%d/cwd", tid);
	assert(readlink(path, str, 1024) != -1);
}


/**
 * for printing syscall data on *replay* stage (as it uses the trace).
 * TODO: fix it so it will be suitable for both stages
 */
void print_syscall(struct task *t, struct trace_frame *trace)
{

	int syscall = trace->recorded_regs.orig_eax;
	int state = trace->state;
	struct user_regs_struct r;
	read_child_registers(t->tid, &r);

	fprintf(stderr,"%u:%d:%d:", trace->global_time, t->rec_tid, t->trace.state);
	if (state == STATE_SYSCALL_ENTRY) {
		fprintf(stderr," event: %d",t->trace.stop_reason);
	}

	if (state == STATE_SYSCALL_EXIT) {
		switch (syscall) {

		/*  int access(const char *pathname, int mode); */
		case SYS_access:
		{
			char *str = read_child_str(t->tid, (void*)r.ebx);
			fprintf(stderr,"access(const char *pathname(%s), int mode(%lx))", str, r.ecx);
			sys_free((void**)str);
			break;
		}


		/* int clock_gettime(clockid_t clk_id, struct timespec *tp); */
		case SYS_clock_gettime:
		{
			fprintf(stderr,"clock_gettime(clockid_t clk_id(%lx), struct timespec *tp(%lx))", r.ebx, r.ecx);
			break;
		}

		/* int close(int fd) */
		case SYS_close:
		{
			fprintf(stderr,"close(int fd(%lx))", r.ebx);
			break;
		}

		/* int gettimeofday(struct timeval *tv, struct timezone *tz); */
		case SYS_gettimeofday:
		{
			fprintf(stderr,"gettimeofday(struct timeval *tv(%lx), struct timezone *tz(%lx))", r.ebx, r.ecx);
			break;
		}

		/* int fstat(int fd, struct stat *buf) */
		case SYS_fstat64:
		{
			fprintf(stderr,"fstat64(int fd(%lx), struct stat *buf(%lx))", r.ebx, r.ecx);
			break;
		}

		/* int futex(int *uaddr, int op, int val, const struct timespec *timeout, int *uaddr2, int val3); */
		case SYS_futex:
		{
			fprintf(stderr,"futex(int *uaddr(%lx), int op(%lx), int val(%lx), const struct timespec *timeout(%lx), int *uaddr2(%lx), int val3(%lx))", r.ebx, r.ecx, r.edx, r.esi, r.edi, r.ebp);
			break;
		}

		/* int ipc(unsigned int call, int first, int second, int third, void *ptr, long fifth); */
		case SYS_ipc:
		{
			fprintf(stderr,"ipc(unsigned int call(%lx), int first(%lx), int second(%lx), int third(%lx), void *ptr(%lx), long fifth(%lx)", r.ebx, r.ecx, r.edx, r.esi, r.edi, r.ebp);
			break;
		}

		/* int _llseek(unsigned int fd, unsigned long offset_high, unsigned long offset_low,
		 loff_t *result, unsigned int whence); */
		case SYS__llseek:
		{
			fprintf(stderr,"_llseek(unsigned int fd(%lx), unsigned long offset_high(%lx), unsigned long offset_low(%lx), loff_t *result(%lx), unsigned int whence(%lx)",
					r.ebx, r.ecx, r.edx, r.esi, r.edi);
			break;
		}

		/* void *mmap2(void *addr, size_t length, int prot,int flags, int fd, off_t pgoffset);*/
		case SYS_mmap2:
		{
			fprintf(stderr,"mmap2(void* addr(%lx), size_t len(%lx), int prot(%lx), int flags(%lx), int fd(%lx),off_t pgoffset(%lx)", r.ebx, r.ecx, r.edx, r.esi, r.edi, r.ebp);
			break;
		}

		/* int munmap(void *addr, size_t length) */
		case SYS_munmap:
		{
			fprintf(stderr,"munmap(void *addr(%lx), size_t length(%lx))", r.ebx, r.ecx);
			break;
		}

		/* int open(const char *pathname, int flags) */
		case SYS_open:
		{
			char *str = read_child_str(t->tid,
						   (void*)r.ebx);
			fprintf(stderr,"open(const char *pathname(%s), int flags(%lx))", str, r.ecx);
			sys_free((void**)&str);
			break;
		}

		/* int poll(struct pollfd *fds, nfds_t nfds, int timeout)*/
		case SYS_poll:
		{
			fprintf(stderr,"poll(struct pollfd *fds(%lx), nfds_t nfds(%lx), int timeout(%lx)", r.ebx, r.ecx, r.edx);
			break;
		}

		/* ssize_t read(int fd, void *buf, size_t count); */
		case SYS_read:
		{
			fprintf(stderr,"read(int fd(%lx), void *buf(%lx), size_t count(%lx)", r.ebx, r.ecx, r.edx);
			break;
		}

		/* int socketcall(int call, unsigned long *args) */
		case SYS_socketcall:
		{
			fprintf(stderr,"socketcall(int call(%ld), unsigned long *args(%lx))", r.ebx, r.ecx);
			break;
		}

		/* int stat(const char *path, struct stat *buf); */
		case SYS_stat64:
		{
			char* str = read_child_str(t->tid,
						   (void*)r.ebx);
			fprintf(stderr,"stat(const char *path(%s), struct stat *buf(%lx))", str, r.ecx);
			sys_free((void**)&str);
			break;
		}

		default:
		{
			fprintf(stderr,"%s(%d)/%d -- global_time %u", syscallname(syscall), syscall, state, trace->global_time);
			break;
		}

		}
	}
	fprintf(stderr, "\n");
}

static void maybe_print_reg_mismatch(int mismatch_behavior, const char* regname,
				     const char* label1, long val1,
				     const char* label2, long val2)
{
	if (mismatch_behavior >= BAIL_ON_MISMATCH) {
		log_err("%s 0x%lx != 0x%lx (%s vs. %s)",
			regname, val1, val2, label1, label2);
	} else if (mismatch_behavior >= LOG_MISMATCHES) {
		log_info("%s 0x%lx != 0x%lx (%s vs. %s)",
			 regname, val1, val2, label1, label2);
	}
}

int compare_register_files(struct task* t,
			   char* name1, const struct user_regs_struct* reg1,
			   char* name2, const struct user_regs_struct* reg2,
			   int mismatch_behavior)
{
	int bail_error = (mismatch_behavior >= BAIL_ON_MISMATCH);
	/* TODO: do any callers use this? */
	int errbit = 0;
	int err = 0;

#define REGCMP(_reg, _bit)						   \
	do {								   \
		if (reg1-> _reg != reg2-> _reg) {			   \
			maybe_print_reg_mismatch(mismatch_behavior, #_reg, \
						 name1, reg1-> _reg,	   \
						 name2, reg2-> _reg);	   \
			err |= (1 << (_bit));				   \
		}							   \
	} while (0)

	REGCMP(eax, ++errbit);
	REGCMP(ebx, ++errbit);
	REGCMP(ecx, ++errbit);
	REGCMP(edx, ++errbit);
	REGCMP(esi, ++errbit);
	REGCMP(edi, ++errbit);
	REGCMP(ebp, ++errbit);
	REGCMP(eip, ++errbit);
	/* The following are eflags that have been observed to be
	 * nondeterministic in practice.  We need to mask them off in
	 * this comparison to prevent replay from diverging. */
	enum {
		/* The linux kernel has been observed to report this
		 * as zero in some states during system calls. It
		 * always seems to be 1 during user-space execution so
		 * we should be able to ignore it. */
		RESERVED_FLAG_1 = 1 << 1,
		/* According to www.logix.cz/michal/doc/i386/chp04-01.htm
		 *
		 *   The RF flag temporarily disables debug exceptions
		 *   so that an instruction can be restarted after a
		 *   debug exception without immediately causing
		 *   another debug exception. Refer to Chapter 12 for
		 *   details.
		 *
		 * Chapter 12 isn't particularly clear on the point,
		 * but the flag appears to be set by |int3|
		 * exceptions.
		 *
		 * This divergence has been observed when continuing a
		 * tracee to an execution target by setting an |int3|
		 * breakpoint, which isn't used during recording.  No
		 * single-stepping was used during the recording
		 * either.
		 */
		RESUME_FLAG = 1 << 16,
		/* It's no longer known why this bit is ignored. */
		CPUID_ENABLED_FLAG = 1 << 21,
	};
	/* check the deterministic eflags */
	const long det_mask =
		~(RESERVED_FLAG_1 | RESUME_FLAG | CPUID_ENABLED_FLAG);
	long eflags1 = (reg1->eflags & det_mask);
	long eflags2 = (reg2->eflags & det_mask);
	if (eflags1 != eflags2) {
		maybe_print_reg_mismatch(mismatch_behavior, "deterministic eflags",
					 name1, eflags1, name2, eflags2);
		err |= (1 << ++errbit);
	}

	assert_exec(t, !bail_error || !err, "Fatal register mismatch");

	return err;
}

void assert_child_regs_are(struct task* t,
			   const struct user_regs_struct* regs,
			   int event, int state)
{
	pid_t tid = t->tid;
	int regs_are_equal;

	read_child_registers(tid, &t->regs);
	regs_are_equal = (0 == compare_register_files(t, "replaying", &t->regs,
						      "recorded", regs,
						      LOG_MISMATCHES));
	if (!regs_are_equal) {
		print_process_mmap(t);
		assert_exec(t, regs_are_equal,
			    "[%s in state %d]", strevent(event), state);
	}
	/* TODO: add perf counter validations (hw int, page faults, insts) */
}

uint64_t str2ull(const char* start, size_t max_size)
{
	int idx = 0;
	while (start[idx] == ' ') {
		idx += 1;
	}

	uint64_t val = 0;
	while (isdigit(start[idx]) && idx <= max_size) {
		char tmp_char[2];
		tmp_char[0] = start[idx];
		tmp_char[1] = '\0';
		int tmp = atoi(tmp_char);
		val *= 10;
		val += tmp;
		idx++;
	}
	return val;
}

long int str2li(const char* start, size_t max_size)
{
	int idx = 0;
	int sign = 1;

	while (start[idx] == ' ') {
		idx += 1;
	}

	if (start[idx] == '-') {
		idx += 1;
		sign = -1;
	}

	long int val = 0;
	while (isdigit(start[idx]) && idx <= max_size) {
		char tmp_char[2];
		tmp_char[0] = start[idx];
		tmp_char[1] = '\0';
		int tmp = atoi(tmp_char);
		val *= 10;
		val += tmp;
		idx++;
	}

	val *= sign;
	return val;
}

void * str2x(const char* start, size_t max_size)
{
	int idx = 0;

	while (start[idx] == ' ') {
		idx++;
	}

	long int val = 0;
	while (idx <= max_size) {
		int tmp = 0;
		if (isdigit(start[idx])) {
			tmp = start[idx] - '0';
		} else if (isalpha(start[idx])) {
			tmp = 10 + start[idx] - 'a';
		} else {
			break;
		}
		val *= 16;
		val += tmp;
		idx++;
	}

	return (void*)val;
}

void read_line(FILE* file, char *buf, int size, char *name)
{
	if (feof(file) || fgets(buf, size, file) == NULL) {
		printf("error reading line in file: %s  -- bailing out\n", name);
		printf("buf: %p  size: %d\n",buf,size);
		perror("");
		exit(-1);
	}
}

int should_dump_memory(struct task* t, int event, int state, int global_time)
{
	const struct flags* flags = rr_flags();

#if defined(FIRST_INTERESTING_EVENT)
	int is_syscall_exit = event >= 0 && state == STATE_SYSCALL_EXIT;
	if (is_syscall_exit
	    && RECORD == flags->option
	    && FIRST_INTERESTING_EVENT <= global_time
	    && global_time <= LAST_INTERESTING_EVENT) {
		return 1;
	}
	if (global_time > LAST_INTERESTING_EVENT) {
		return 0;
	}
#endif
	return (flags->dump_on == event || flags->dump_on == DUMP_ON_ALL
		|| flags->dump_at == global_time);
}

static int dump_process_memory_iterator(void* it_data, struct task* t,
					const struct map_iterator_data* data)
{
	FILE* dump_file = it_data;
	const unsigned* buf = data->mem;
	void* start_addr = data->info.start_addr;
	int i;

	if (!buf) {
		/* This segment was filtered by debugging code. */
		return CONTINUE_ITERATING;
	}
	if (is_start_of_scratch_region(start_addr)) {
		/* Scratch regions will diverge between
		 * recording/replay, so including them in memory dumps
		 * makes comparing record/replay dumps very noisy. */
		return CONTINUE_ITERATING;
	}

	fprintf(dump_file,"%s\n", data->raw_map_line);
	for (i = 0 ; i < data->mem_len / sizeof(*buf); i += 1) {
		unsigned word = buf[i];
		fprintf(dump_file,"0x%08x | [%p]\n", word,
			start_addr + i * sizeof(*buf));
	}

	return CONTINUE_ITERATING;
}

static int dump_process_memory_segment_filter(
	void* filt_data, struct task* t,
	const struct mapped_segment_info* info)
{
	/* For debugging purposes, add segment filtering here, for
	 * example
	if (!strstr(info->name, "[stack]")) {
		return 0;
	}
	*/
	return 1;
}

static void format_dump_filename(struct task* t, const char* tag,
				 char* filename, size_t filename_size)
{
	snprintf(filename, filename_size - 1, "%s/%d_%d_%s",
		 get_trace_path(), t->rec_tid, get_global_time(), tag);
}

void dump_process_memory(struct task* t, const char* tag)
{
	char filename[PATH_MAX];
	FILE* dump_file;

	format_dump_filename(t, tag, filename, sizeof(filename));
	dump_file = fopen(filename,"w");

	/* flush all files in case we partially record
	 * TODO: what does that mean? */
	flush_trace_files();

	iterate_memory_map(t, dump_process_memory_iterator, dump_file,
			   dump_process_memory_segment_filter, NULL);
	fclose(dump_file);
}

static void notify_checksum_error(struct task* t,
				  unsigned checksum, unsigned rec_checksum,
				  const struct map_iterator_data* data)
{
	int event = t->trace.stop_reason;
	char cur_dump[PATH_MAX];
	char rec_dump[PATH_MAX];

	dump_process_memory(t, "checksum_error");

	/* TODO: if the right recorder memory dump is present,
	 * automatically compare them, taking the oddball
	 * not-mapped-during-replay region(s) into account.  And if
	 * not present, tell the user how to make one in a future
	 * run. */
	format_dump_filename(t, "checksum_error", cur_dump, sizeof(cur_dump));
	format_dump_filename(t, "rec", rec_dump, sizeof(rec_dump));

	assert_exec(t, checksum == rec_checksum,
"Divergence in contents of memory segment after '%s':\n"
"\n"
"%s"
"    (recorded checksum:0x%x; replaying checksum:0x%x)\n"
"\n"
"Dumped current memory contents to %s. If you've created a memory dump for\n"
"the '%s' event (line %d) during recording by using, for example with\n"
"the args\n"
"\n"
"$ rr --dump-at=%d record ...\n"
"\n"
"then you can use the following to determine which memory cells differ:\n"
"\n"
"$ lcmp %s %s > mem-diverge.diff\n"
		    , strevent(event),
		    data->raw_map_line,
		    rec_checksum, checksum,
		    cur_dump, strevent(event),  get_global_time(),
		    get_global_time(),
		    rec_dump, cur_dump);
}

/**
 * This helper does the heavy lifting of storing or validating
 * checksums.  The iterator data determines which behavior the helper
 * function takes on, and to/from which file it writes/read.
 */
struct checksum_iterator_data {
	enum { STORE_CHECKSUMS, VALIDATE_CHECKSUMS } mode;
	FILE* checksums_file;
};
static int checksum_iterator(void* it_data, struct task* t,
			     const struct map_iterator_data* data)
{
	struct checksum_iterator_data* c = it_data;
	unsigned* buf = data->mem;
	ssize_t valid_mem_len = data->mem_len;
	unsigned checksum = 0;
	int i;

	if (data->info.name ==
	    strstr(data->info.name, SYSCALLBUF_SHMEM_FILENAME_PREFIX)) {
		/* The syscallbuf consists of a region that's written
		 * deterministically wrt the trace events, and a
		 * region that's written nondeterministically in the
		 * same way as trace scratch buffers.  The
		 * deterministic region comprises committed syscallbuf
		 * records, and possibly the one pending record
		 * metadata.  The nondeterministic region starts at
		 * the "extra data" for the possibly one pending
		 * record.
		 *
		 * So here, we set things up so that we only checksum
		 * the deterministic region. */
		void* child_hdr = data->info.start_addr;
		struct syscallbuf_hdr* hdr = read_child_data(t, sizeof(*hdr),
							     child_hdr);
		valid_mem_len = sizeof(*hdr) + hdr->num_rec_bytes +
				sizeof(struct syscallbuf_record);
		sys_free((void**)&hdr);
	}

	/* If this segment was filtered, then data->mem_len will be 0
	 * to indicate nothing was read.  And data->mem will be NULL
	 * to double-check that.  In that case, the checksum will just
	 * be 0. */
	for (i = 0; i < valid_mem_len / sizeof(*buf); ++i) {
		checksum += buf[i];
	}

	if (STORE_CHECKSUMS == c->mode) {
		fprintf(c->checksums_file,"(%x) %s",
			checksum, data->raw_map_line);
	} else {
		char line[1024];
		unsigned rec_checksum;
		void* rec_start_addr;
		void* rec_end_addr;
		int nparsed;

		fgets(line, sizeof(line), c->checksums_file);
		nparsed = sscanf(line, "(%x) %p-%p", &rec_checksum,
				 &rec_start_addr, &rec_end_addr);
		assert_exec(t, 3 == nparsed, "Only parsed %d items", nparsed);

		assert_exec(t, (rec_start_addr == data->info.start_addr
				&& rec_end_addr == data->info.end_addr),
			    "Segment %p-%p changed to %p-%p??",
			    rec_start_addr, rec_end_addr,
			    data->info.start_addr, data->info.end_addr);

		if (is_start_of_scratch_region(rec_start_addr)) {
			/* Replay doesn't touch scratch regions, so
			 * their contents are allowed to diverge.
			 * Tracees can't observe those segments unless
			 * they do something sneaky (or disastrously
			 * buggy). */
			debug("Not validating scratch starting at %p",
			      rec_start_addr);
			return CONTINUE_ITERATING;
		}
	 	if (checksum != rec_checksum) {
			notify_checksum_error(t, checksum, rec_checksum, data);
		}
	}
	return CONTINUE_ITERATING;
}

static int checksum_segment_filter(void* filt_data, struct task* t,
				   const struct mapped_segment_info* info)
{
	struct stat st;
	int may_diverge;

	if (stat(info->name, &st)) {
		/* If there's no persistent resource backing this
		 * mapping, we should expect it to change. */
		debug("CHECKSUMMING unlinked '%s'", info->name);
		return 1;
	}
	/* If we're pretty sure the backing resource is effectively
	 * immutable, skip checksumming, it's a waste of time.  Except
	 * if the mapping is mutable, for example the rw data segment
	 * of a system library, then it's interesting. */
	may_diverge = (should_copy_mmap_region(info->name, &st,
					       info->prot, info->flags,
					       DONT_WARN_SHARED_WRITEABLE)
		       || (PROT_WRITE & info->prot));
	debug("%s '%s'",
	      may_diverge ? "CHECKSUMMING" : "  skipping", info->name);
	return may_diverge;
}

/**
 * Either create and store checksums for each segment mapped in |t|'s
 * address space, or validate an existing computed checksum.  Behavior
 * is selected by |mode|.
 */
static void iterate_checksums(struct task* t, int mode)
{
	struct checksum_iterator_data c = { 0 };
	char filename[PATH_MAX];
	const char* fmode = (STORE_CHECKSUMS == mode) ? "w" : "r";

	c.mode = mode;
	snprintf(filename, sizeof(filename) - 1, "%s/%d_%d",
		 get_trace_path(), get_global_time(), t->rec_tid);
	c.checksums_file = fopen(filename, fmode);

	iterate_memory_map(t, checksum_iterator, &c,
			   checksum_segment_filter, NULL);

	fclose(c.checksums_file);
}

int should_checksum(struct task* t, int event, int state, int global_time)
{
	int checksum = rr_flags()->checksum;
	int is_syscall_exit = (event >= 0 && state == STATE_SYSCALL_EXIT);

#if defined(FIRST_INTERESTING_EVENT)
	if (is_syscall_exit
	    && FIRST_INTERESTING_EVENT <= global_time
	    && global_time <= LAST_INTERESTING_EVENT) {
		return 1;
	}
	if (global_time > LAST_INTERESTING_EVENT) {
		return 0;
	}
#endif
	if (CHECKSUM_NONE == checksum) {
		return 0;
	}
	if (CHECKSUM_ALL == checksum) {
		return 1;
	}
	if (CHECKSUM_SYSCALL == checksum) {
		return is_syscall_exit;
	}
	/* |checksum| is a global time point. */
	return checksum <= global_time;
}

void checksum_process_memory(struct task* t)
{
	/* flush all files in case we start replaying while still
	 * recording */
	flush_trace_files();

	iterate_checksums(t, STORE_CHECKSUMS);
}

void validate_process_memory(struct task* t)
{
	iterate_checksums(t, VALIDATE_CHECKSUMS);
}

/**
 * @start_addr: start address of where code should be injected
 * @code_size : given in bytes - must be a multiple of 4!
 */
struct current_state_buffer* init_code_injection(pid_t pid, void* start_addr, int code_size)
{
	//check if code size is a multiple of 4
	assert(code_size % 4 == 0);

	struct current_state_buffer* buf = sys_malloc(sizeof(struct current_state_buffer));
	buf->pid = pid;

	//save the current state of the register file
	read_child_registers(pid, &(buf->regs));

	//save original instructions; assure word alignment
	long* tmp = (long*) ((unsigned long) start_addr & ~0x3);
	long* code_buffer = sys_malloc(code_size + (2 * sizeof(long)));

	int i = 0;
	while ((void *) tmp + i < (void *) start_addr + code_size) {
		//TODO: re-implemnt read_code
		//code_buffer[i] = read_child_code(pid, tmp + i);
		//	printf("read instruction: %lx\n",code_buffer[i]);
		i++;
	}

	buf->code_size = i * 4;
	buf->code_buffer = code_buffer;
	buf->start_addr = tmp;
	return buf;
}

void restore_original_state(struct current_state_buffer* buf)
{
	//restoring the original state involves two steps:
	//1. restore register file (including eip)
	write_child_registers(buf->pid, &(buf->regs));

	//2. copy the original code back to the child
	int i;
	for (i = 0; i < buf->code_size / 4; i++) {
		write_child_code(buf->pid, buf->start_addr + i, buf->code_buffer[i]);
	}
}

void cleanup_code_injection(struct current_state_buffer* buf)
{
	sys_free((void**) &buf->code_buffer);
	sys_free((void**) &buf);
}

void add_scratch(void *ptr, int size) {
	scratch_table[scratch_table_size++] = ptr;
	scratch_overall_size += size;
}

void add_sig_handler(pid_t tid, unsigned int signum, struct sigaction * sa){
	assert(signum < SIGRTMAX + 1);
	if (sig_handler_table[tid][signum] != NULL)
		sys_free((void**)&(sig_handler_table[tid][signum]));
	sig_handler_table[tid][signum] = sys_malloc(sizeof(struct sigaction));
	memcpy(sig_handler_table[tid][signum], sa, sizeof(struct sigaction));
}

struct sigaction * get_sig_handler(pid_t tid, unsigned int signum){
	assert(signum < SIGRTMAX + 1);
	return sig_handler_table[tid][signum];
}

void copy_syscall_arg_regs(struct user_regs_struct* to,
			   const struct user_regs_struct* from)
{
	to->ebx = from->ebx;
	to->ecx = from->ecx;
	to->edx = from->edx;
	to->esi = from->esi;
	to->edi = from->edi;
	to->ebp = from->ebp;
}

void record_struct_msghdr(struct task* t, struct msghdr* child_msghdr)
{
	struct msghdr* msg = read_child_data(t, sizeof(*msg), child_msghdr);
	struct iovec* iov;

	/* Record the entire struct, because some of the direct fields
	 * are written as inoutparams. */
	record_child_data(t, sizeof(*child_msghdr), child_msghdr);
	record_child_data(t, msg->msg_namelen, msg->msg_name);

	assert("TODO: record more than 1 iov" && msg->msg_iovlen == 1);

	record_child_data(t, sizeof(struct iovec), msg->msg_iov);
	iov = read_child_data(t, sizeof(struct iovec), msg->msg_iov);
	record_child_data(t, iov->iov_len, iov->iov_base);

	record_child_data(t, msg->msg_controllen, msg->msg_control);

	sys_free((void**) &iov);
	sys_free((void**) &msg);
}

void record_struct_mmsghdr(struct task* t, struct mmsghdr* child_mmsghdr)
{
	/* struct mmsghdr has an inline struct msghdr as its first
	 * field, so it's OK to make this "cast". */
	record_struct_msghdr(t, (void*)child_mmsghdr);
	/* We additionally have to record the outparam number of
	 * received bytes. */
	record_child_data(t, sizeof(child_mmsghdr->msg_len),
			  &child_mmsghdr->msg_len);
}

void restore_struct_msghdr(struct task* t, struct msghdr* child_msghdr)
{
	/* TODO: with above, generalize for arbitrary msghdr. */
	const int num_emu_args = 5;
	int i;

	for (i = 0; i < num_emu_args; ++i) {
		set_child_data(t);
	}
}

void restore_struct_mmsghdr(struct task* t, struct mmsghdr* child_mmsghdr)
{
	restore_struct_msghdr(t, (void*)child_mmsghdr);
	set_child_data(t);
}

int is_desched_event_syscall(struct task* t,
			     const struct user_regs_struct* regs)
{
	return (SYS_ioctl == regs->orig_eax
		&& (t->desched_fd_child == regs->ebx
		    || t->desched_fd_child == REPLAY_DESCHED_EVENT_FD));
}

int is_arm_desched_event_syscall(struct task* t,
				 const struct user_regs_struct* regs)
{
	return (is_desched_event_syscall(t, regs)
		&& PERF_EVENT_IOC_ENABLE == regs->ecx);
}

int is_disarm_desched_event_syscall(struct task* t,
				    const struct user_regs_struct* regs)
{
	return (is_desched_event_syscall(t, regs)
		&& PERF_EVENT_IOC_DISABLE == regs->ecx);
}

int is_syscall_restart(struct task* t, int syscallno,
		       const struct user_regs_struct* regs)
{
	int must_restart = (SYS_restart_syscall == syscallno);
	int is_restart = 0;
	const struct user_regs_struct* old_regs;

	if (EV_SYSCALL_INTERRUPTION != t->ev->type) {
		goto done;
	}
	/* It's possible for the tracee to resume after a sighandler
	 * with a fresh syscall that happens to be the same as the one
	 * that was interrupted.  So we check here if the args are the
	 * same.
	 *
	 * Of course, it's possible (but less likely) for the tracee
	 * to incidentally resume with a fresh syscall that just
	 * happens to have the same *arguments* too.  But in that
	 * case, we would usually set up scratch buffers etc the same
	 * was as for the original interrupted syscall, so we just
	 * save a step here.
	 *
	 * TODO: it's possible for arg structures to be mutated
	 * between the original call and restarted call in such a way
	 * that it might change the scratch allocation decisions. */
	if (SYS_restart_syscall == syscallno) {
		syscallno = t->ev->syscall.no;
		debug("  (SYS_restart_syscall)");
	}
	old_regs = &t->ev->syscall.regs;
	is_restart = (t->ev->syscall.no == syscallno
		      && old_regs->ebx == regs->ebx
		      && old_regs->ecx == regs->ecx
		      && old_regs->edx == regs->edx
		      && old_regs->esi == regs->esi
		      && old_regs->edi == regs->edi
		      && old_regs->ebp == regs->ebp);
	if (!is_restart) {
		debug("  interrupted %s != %s or args differ",
		      syscallname(t->ev->syscall.no), syscallname(syscallno));
	}

done:
	assert_exec(t, !must_restart || is_restart,
		    "Must restart %s but won't", syscallname(syscallno));
	if (is_restart) {
		debug("  restart of %s", syscallname(syscallno));
	}
	return is_restart;
}

static int is_tmp_file(const char* path)
{
	struct statfs sfs;
	statfs(path, &sfs);
	return TMPFS_MAGIC == sfs.f_type;
}

int should_copy_mmap_region(const char* filename, struct stat* stat,
			    int prot, int flags,
			    int warn_shared_writeable)
{
	int private_mapping = (flags & MAP_PRIVATE);
	int can_write_file;

	if (is_tmp_file(filename)) {
		debug("  copying file on tmpfs");
		return 1;
	}
	if (private_mapping && (prot & PROT_EXEC)) {
		/* We currently don't record the images that we
		 * exec(). Since we're being optimistic there (*cough*
		 * *cough*), we're doing no worse (in theory) by being
		 * optimistic about the shared libraries too, most of
		 * which are system libraries. */
		debug("  (no copy for +x private mapping %s)", filename);
		return 0;
	}
	if (private_mapping && (0111 & stat->st_mode)) {
		/* A private mapping of an executable file usually
		 * indicates mapping data sections of object files.
		 * Since we're already assuming those change very
		 * infrequently, we can avoid copying the data
		 * sections too. */
		debug("  (no copy for private mapping of +x %s)", filename);
		return 0;
	}

	/* TODO: using "can the euid of the rr process write this
	 * file" as an approximation of whether the tracee can write
	 * the file.  If the tracee is messing around with
	 * set*[gu]id(), the real answer may be different. */
	can_write_file = (0 == access(filename, W_OK));

	if (!can_write_file && 0 == stat->st_uid) {
		assert(!(prot & PROT_WRITE));
		/* Mapping a file owned by root: we don't care if this
		 * was a PRIVATE or SHARED mapping, because unless the
		 * program is disastrously buggy or unlucky, the
		 * mapping is effectively PRIVATE.  Bad luck can come
		 * from this program running during a system update,
		 * or a user being added, which is probably less
		 * frequent than even system updates.
		 *
		 * XXX what about the fontconfig cache files? */
		debug("  (no copy for root-owned %s)", filename);
		return 0;
	}
	if (private_mapping) {
		/* Some programs (at least Firefox) have been observed
		 * to use cache files that are expected to be
		 * consistent and unchanged during the bulk of
		 * execution, but may be destroyed or mutated at
		 * shutdown in preparation for the next session.  We
		 * don't otherwise know what to do with private
		 * mappings, so err on the safe side.
		 *
		 * TODO: could get into dirty heuristics here like
		 * trying to match "cache" in the filename ...	 */
		debug("  copying private mapping of non-system -x %s",
		      filename);
		return 1;
	}
	if (!(0222 & stat->st_mode)) {
		/* We couldn't write the file because it's read only.
		 * But it's not a root-owned file (therefore not a
		 * system file), so it's likely that it could be
		 * temporary.  Copy it. */
		debug("  copying read-only, non-system file");
		return 1;
	}
	if (!can_write_file) {
		/* mmap'ing another user's (non-system) files?  Highly
		 * irregular ... */
		fatal("Unhandled mmap %s(prot:%x%s); uid:%d mode:%o",
		      filename, prot, (flags & MAP_SHARED) ? ";SHARED" : "",
		      stat->st_uid, stat->st_mode);
	}
	/* Shared mapping that we can write.  Should assume that the
	 * mapping is likely to change. */
	debug("  copying writeable SHARED mapping %s", filename);
	if (PROT_WRITE | prot) {
#ifndef DEBUGTAG
		if (warn_shared_writeable)
#endif
		log_warn("%s is SHARED|WRITEABLE; that's not handled correctly yet. Optimistically hoping it's not written by programs outside the rr tracee tree.",
			 filename);
	}
	return 1;
}

void prepare_remote_syscalls(struct task* t,
			     struct current_state_buffer* state)
{
	pid_t tid = t->tid;
	byte syscall_insn[] = { 0xcd, 0x80 };

	/* Save current state of |t|. */
	memset(state, 0, sizeof(*state));
	state->pid = t->tid;
	read_child_registers(tid, &state->regs);
	state->code_size = sizeof(syscall_insn);
	state->start_addr = (void*)state->regs.eip;
	state->code_buffer =
		read_child_data(t, state->code_size, state->start_addr);

	/* Inject phony syscall instruction. */
	write_child_data(t, state->code_size, state->start_addr,
			 syscall_insn);
}

void* push_tmp_str(struct task* t, struct current_state_buffer* state,
		   const char* str, struct restore_mem* mem)
{
	pid_t tid = t->tid;

	mem->len = strlen(str) + 1/*null byte*/;
	mem->saved_sp = (void*)state->regs.esp;

	state->regs.esp -= mem->len;
	write_child_registers(tid, &state->regs);
	mem->addr = (void*)state->regs.esp;

	mem->data = read_child_data(t, mem->len, mem->addr);

	write_child_data(t, mem->len, mem->addr, str);

	return mem->addr;
}

void pop_tmp_mem(struct task* t, struct current_state_buffer* state,
		 struct restore_mem* mem)
{
	pid_t tid = t->tid;

	assert(mem->saved_sp == (void*)state->regs.esp + mem->len);

	write_child_data(t, mem->len, mem->addr, mem->data);
	sys_free((void**)&mem->data);

	state->regs.esp += mem->len;
	write_child_registers(tid, &state->regs);
}

long remote_syscall(struct task* t, struct current_state_buffer* state,
		    int wait, int syscallno,
		    long a1, long a2, long a3, long a4, long a5, long a6)
{
	pid_t tid = t->tid;
	struct user_regs_struct callregs;

	assert(tid == state->pid);

	/* Prepare syscall arguments. */
	memcpy(&callregs, &state->regs, sizeof(callregs));
	callregs.eax = syscallno;
	callregs.ebx = a1;
	callregs.ecx = a2;
	callregs.edx = a3;
	callregs.esi = a4;
	callregs.edi = a5;
	callregs.ebp = a6;
	write_child_registers(tid, &callregs);

	/* Advance to syscall entry. */
	sys_ptrace_syscall(tid);
	sys_waitpid(tid, &t->status);

	/* Skip past a seccomp trace, if we happened to see one. */
	if (GET_PTRACE_EVENT(t->status) == PTRACE_EVENT_SECCOMP
	    /* XXX this is a special case for ubuntu 12.04.  revisit
	     * this check if an event is added with number 8 (just
	     * after SECCOMP */
	    || GET_PTRACE_EVENT(t->status) == PTRACE_EVENT_SECCOMP_OBSOLETE) {
		sys_ptrace_syscall(tid);
		sys_waitpid(tid, &t->status);
	}
	assert(GET_PTRACE_EVENT(t->status) == 0);

	read_child_registers(t->tid, &callregs);
	assert_exec(t, callregs.orig_eax == syscallno,
		    "Should be entering %s, but instead at %s",
		    syscallname(syscallno), syscallname(callregs.orig_eax));

	/* Start running the syscall. */
	sys_ptrace_syscall(tid);
	if (WAIT == wait) {
		return wait_remote_syscall(t, state, syscallno);
	}
	return 0;
}

long wait_remote_syscall(struct task* t, struct current_state_buffer* state,
			 int syscallno)
{
	pid_t tid = t->tid;
	struct user_regs_struct regs;
	/* Wait for syscall-exit trap. */
	sys_waitpid(tid, &t->status);

	read_child_registers(t->tid, &regs);
	assert_exec(t, regs.orig_eax == syscallno,
		    "Should be entering %s, but instead at %s",
		    syscallname(syscallno), syscallname(regs.orig_eax));

	return regs.eax;
}

void finish_remote_syscalls(struct task* t,
			    struct current_state_buffer* state)
{
	pid_t tid = t->tid;

	assert(tid == state->pid);

	/* Restore stomped instruction. */
	write_child_data(t, state->code_size, state->start_addr,
			 state->code_buffer);
	sys_free((void**)&state->code_buffer);

	/* Restore stomped registers. */
	write_child_registers(tid, &state->regs);
}

/**
 * Share |fd| to the other side of |sock|.
 */
static void send_fd(int fd, int sock)
{
	struct msghdr msg;
	int dummy_fd = 0;
	struct iovec data;
	struct cmsghdr* cmsg;
	char cmsgbuf[CMSG_SPACE(sizeof(int))];

	memset(&msg, 0, sizeof(msg));

	/* We must always send the same value to the child so that
	 * nondeterministic values, like fd numbers in this process,
	 * don't leak into its address space. */
	data.iov_base = &dummy_fd;
	data.iov_len = sizeof(dummy_fd);
	msg.msg_iov = &data;
	msg.msg_iovlen = 1;

	msg.msg_control = cmsgbuf;
	msg.msg_controllen = CMSG_LEN(sizeof(int));

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	*(int*)CMSG_DATA(cmsg) = fd;

	if (0 >= sendmsg(sock, &msg, 0)) {
		fatal("Failed to send fd");
	}
}

/**
 * Block until receiving an fd the other side of |sock| sent us, then
 * return the fd (valid in this address space).  Optionally return the
 * remote fd number that was shared to us in |remote_fdno|.
 */
static int recv_fd(int sock, int* remote_fdno)
{
	struct msghdr msg;
	int fd, remote_fd;
	struct iovec data;
	struct cmsghdr* cmsg;
	char cmsgbuf[CMSG_SPACE(sizeof(int))];

	memset(&msg, 0, sizeof(msg));

	data.iov_base = &remote_fd;
	data.iov_len = sizeof(remote_fd);
	msg.msg_iov = &data;
	msg.msg_iovlen = 1;

	msg.msg_control = cmsgbuf;
	msg.msg_controllen = sizeof(cmsgbuf);

	if (0 >= recvmsg(sock, &msg, 0)) {
		fatal("Failed to receive fd");
	}

	cmsg = CMSG_FIRSTHDR(&msg);
	assert(cmsg->cmsg_level == SOL_SOCKET
	       && cmsg->cmsg_type == SCM_RIGHTS);

	fd = *(int*)CMSG_DATA(cmsg);
	if (remote_fdno) {
		*remote_fdno = remote_fd;
	}

	return fd;
}

static void write_socketcall_args(struct task* t, void* child_args_vec,
				  long arg1, long arg2, long arg3)
{
	struct socketcall_args args = { { arg1, arg2, arg3 } };
	write_child_data(t, sizeof(args), child_args_vec, &args);
}

void* init_syscall_buffer(struct task* t, struct current_state_buffer* state,
			  struct rrcall_init_buffers_params* args,
			  void* map_hint, int share_desched_fd)
{
	pid_t tid = t->tid;
	char shmem_filename[PATH_MAX];
	struct sockaddr_un addr;
	long child_ret;
	int listen_sock, sock, child_sock;
	int shmem_fd, child_shmem_fd;
	void* map_addr;
	void* child_map_addr;
	void* tmp;
	int zero = 0;

	t->untraced_syscall_ip = args->untraced_syscall_ip;
	snprintf(shmem_filename, sizeof(shmem_filename) - 1,
		 SYSCALLBUF_SHMEM_FILENAME_PREFIX "%d", tid);
	/* NB: the sockaddr prepared by the child uses the recorded
	 * tid, so always must here. */
	prepare_syscallbuf_socket_addr(&addr, t->rec_tid);

	/* Create the segment we'll share with the tracee. */
	if (0 > (shmem_fd = open(shmem_filename, O_CREAT | O_RDWR, 0640))) {
		fatal("Failed to open shmem file %s", shmem_filename);
	}
	/* Remove the fs name; we're about to "anonymously" share our
	 * fd to the tracee. */
	unlink(shmem_filename);
	if (ftruncate(shmem_fd, SYSCALLBUF_BUFFER_SIZE)) {
		fatal("Failed to resize syscall buffer shmem");
	}

	/* Bind the server socket, but don't start listening yet. */
	listen_sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (bind(listen_sock, (struct sockaddr*)&addr, sizeof(addr))) {
		fatal("Failed to bind listen socket");
	}
	if (listen(listen_sock, 1)) {
		fatal("Failed to mark listening for listen socket");
	}

	/* Initiate tracee connect(), but don't wait for it to
	 * finish. */
	write_socketcall_args(t, args->args_vec, AF_UNIX, SOCK_STREAM, 0);
	child_sock = remote_syscall2(t, state, SYS_socketcall,
				     SYS_SOCKET, args->args_vec);
	if (0 > child_sock) {
		errno = -child_sock;
		fatal("Failed to create child socket");
	}
	write_socketcall_args(t, args->args_vec, child_sock,
			      (uintptr_t)args->sockaddr,
			      sizeof(*args->sockaddr));
	remote_syscall(t, state, DONT_WAIT, SYS_socketcall,
		       SYS_CONNECT, (uintptr_t)args->args_vec, 0, 0, 0, 0);
	/* Now the child is waiting for us to accept it. */

	/* Accept the child's connection and finish its syscall.
	 *
	 * XXX could be really anal and check credentials of
	 * connecting endpoint ... */
	sock = accept(listen_sock, NULL, NULL);
	if ((child_ret = wait_remote_syscall(t, state, SYS_socketcall))) {
		errno = -child_ret;
		fatal("Failed to connect() in tracee");
	}
	/* Socket name not needed anymore. */
	unlink(addr.sun_path);

	if (SHARE_DESCHED_EVENT_FD == share_desched_fd) {
		/* Pull the puppet strings to have the child share its
		 * desched counter with us.  Similarly to above, we
		 * DONT_WAIT on the call to finish, since it's likely
		 * not defined whether the sendmsg() may block on our
		 * recvmsg()ing what the tracee sent us (in which case
		 * we would deadlock with the tracee). */
		write_socketcall_args(t, args->args_vec, child_sock,
				      (uintptr_t)args->msg, 0);
		remote_syscall(t, state, DONT_WAIT, SYS_socketcall,
			       SYS_SENDMSG, (uintptr_t)args->args_vec,
			       0, 0, 0, 0);
		/* Child may be waiting on our recvmsg(). */

		/* Read the shared fd and finish the child's syscall. */
		t->desched_fd = recv_fd(sock, &t->desched_fd_child);
		if (0 >= wait_remote_syscall(t, state, SYS_socketcall)) {
			errno = -child_ret;
			fatal("Failed to sendmsg() in tracee");
		}
	} else {
		t->desched_fd_child = REPLAY_DESCHED_EVENT_FD;
	}

	/* Share the shmem fd with the child.  It's ok to reuse the
	 * |child_msg| buffer. */
	send_fd(shmem_fd, sock);
	write_socketcall_args(t, args->args_vec, child_sock,
			      (uintptr_t)args->msg, 0);
	child_ret = remote_syscall2(t, state, SYS_socketcall,
				    SYS_RECVMSG, args->args_vec);
	if (0 >= child_ret) {
		errno = -child_ret;
		fatal("Failed to recvmsg() shared fd in tracee");
	}

	/* Get the newly-allocated fd. */
	tmp = read_child_data(t, sizeof(child_shmem_fd), args->fdptr);
	child_shmem_fd = *(int*)tmp;
	sys_free(&tmp);

	/* Zero out the child buffers we use here.  They contain
	 * "real" fds, which in general will not be the same across
	 * record/replay. */
	write_socketcall_args(t, args->args_vec, 0, 0, 0);
	write_child_data(t, sizeof(zero), args->fdptr, &zero);

	/* Socket magic is now done. */
	close(listen_sock);
	close(sock);
	remote_syscall1(t, state, SYS_close, child_sock);

	/* Map the segment in our address space and in the
	 * tracee's. */
	if ((void*)-1 ==
	    (map_addr = mmap(NULL, SYSCALLBUF_BUFFER_SIZE,
			     PROT_READ | PROT_WRITE, MAP_SHARED,
			     shmem_fd, 0))) {
		fatal("Failed to mmap shmem region");
	}
	t->num_syscallbuf_bytes = args->num_syscallbuf_bytes
				= SYSCALLBUF_BUFFER_SIZE;
	child_map_addr = (void*)remote_syscall6(t, state, SYS_mmap2,
						map_hint,
						args->num_syscallbuf_bytes,
						PROT_READ | PROT_WRITE,
						MAP_SHARED, child_shmem_fd, 0);
	t->syscallbuf_child = args->syscallbuf_ptr = child_map_addr;
	t->syscallbuf_hdr = map_addr;
	/* No entries to begin with. */
	memset(t->syscallbuf_hdr, 0, sizeof(*t->syscallbuf_hdr));

	close(shmem_fd);
	remote_syscall1(t, state, SYS_close, child_shmem_fd);

	return child_map_addr;
}

void* init_buffers(struct task* t, void* map_hint, int share_desched_fd)
{
	struct current_state_buffer state;
	void* child_args;
	struct rrcall_init_buffers_params* args;
	void* child_map_addr = NULL;

	/* NB: the tracee can't be interrupted with a signal while
	 * we're processing the rrcall, because it's masked off all
	 * signals. */

	prepare_remote_syscalls(t, &state);
	/* Arguments to the rrcall. */
	child_args = (void*)state.regs.ebx;
	args = read_child_data(t, sizeof(*args), child_args);

	args->scratch_ptr = t->scratch_ptr;
	args->num_scratch_bytes = t->scratch_size;
	if (args->syscallbuf_enabled) {
		child_map_addr =
			init_syscall_buffer(t, &state, args,
					    map_hint, share_desched_fd);
	} else {
		args->syscallbuf_ptr = NULL;
		args->num_syscallbuf_bytes = 0;
	}

	/* Return the mapped buffers to the child. */
	write_child_data(t, sizeof(*args), child_args, args);
	sys_free((void**)&args);

	/* The tracee doesn't need this addr returned, because it's
	 * already written to the inout |args| param, but we stash it
	 * away in the return value slot so that we can easily check
	 * that we map the segment at the same addr during replay. */
	state.regs.eax = (uintptr_t)child_map_addr;
	finish_remote_syscalls(t, &state);

	return child_map_addr;
}
