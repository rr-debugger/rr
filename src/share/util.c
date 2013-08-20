/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include "util.h"

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <libdis.h>
#include <limits.h>
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

/* The tracee doesn't open the desched event fd during replay, so it
 * can't be shared to this process.  We pretend that the tracee shared
 * this magic fd number with us and then give it a free pass for fd
 * checks that include this fd. */
#define REPLAY_DESCHED_EVENT_FD -123
#define NUM_MAX_MAPS 1024

static void* scratch_table[MAX_TID] = {NULL} ;
static size_t scratch_table_size = 0;
static size_t scratch_overall_size = 0;

static struct sigaction * sig_handler_table[MAX_TID][_NSIG] = { {NULL} };

static size_t num_shared_maps = 0;
static void* shared_maps_starts[MAX_TID] = {0};
static void* shared_maps_ends[MAX_TID] = {0};

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

double now_sec()
{
	struct timespec tp;
	clock_gettime(CLOCK_MONOTONIC, &tp);
	return (double)tp.tv_sec + (double)tp.tv_nsec / 1e9;
}

int nanosleep_nointr(const struct timespec* ts)
{
	struct timespec req = *ts;
	struct timespec rem;
	int err;
	do {
		err = nanosleep(&req, &rem);
		if (errno == EINTR) {
			err = 0;
		}
		req = rem;
	} while (err == 0 && req.tv_sec > 0 && req.tv_nsec > 0);
	return err;

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

static unsigned long str2i(char* str, int base)
{
	char *endptr;

	errno = 0;
	unsigned long val = strtoul(str, &endptr, base);

	if ((errno == ERANGE && val == ULONG_MAX) || (errno != 0 && val == 0)) {
		log_err("strtoul failed");
		exit(EXIT_FAILURE);
	}

	if (endptr == str) {
		log_err("strtoul: No digits were found\n");
		exit(EXIT_FAILURE);
	}

	return val;
}

void get_eip_info(pid_t tid)
{
	unsigned long eip = read_child_eip(tid);
	char buf[100];
	sprintf(buf, "/proc/%d/maps", tid);
	FILE* maps = sys_fopen(buf, "r");

	char* line = sys_malloc(512);

	unsigned long start, end;

	do {
		read_line(maps, line, 512, "maps");

		char addr[9];

		memcpy(addr, line, 8);
		addr[8] = '\0';
		start = str2i(addr, 16);

		memcpy(addr, line + 9, 8);
		addr[8] = '\0';

		end = str2i(addr, 16);
	} while (!((eip >= start) && (eip <= end)));

	char* tmp = sys_malloc(128);
	memcpy(tmp, line + 49, 128);
	fprintf(stderr, "file: %s", line);
	fprintf(stderr, "offset: %lx\n", eip - start);
	sys_free((void**) &tmp);
	sys_fclose(maps);
	sys_free((void**) &line);
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

void mprotect_child_region(struct task * t, void * addr, int prot) {
	struct user_regs_struct mprotect_call;
	read_child_registers(t->tid,&mprotect_call);
	addr = (void*)((int)addr & PAGE_MASK); // align the address
	size_t length = get_mmaped_region_end(t,addr) - addr;
	mprotect_call.eax = SYS_mprotect;
	mprotect_call.ebx = (uintptr_t)addr;
	mprotect_call.ecx = length;
	mprotect_call.edx = prot;
	int retval = inject_and_execute_syscall(t,&mprotect_call);
	(void)retval;
	assert(retval == 0);
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
		perror("error reading child memory maps\n");
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

int compare_register_files(char* name1, const struct user_regs_struct* reg1,
			   char* name2, const struct user_regs_struct* reg2,
			   int mismatch_behavior)
{
	int print = (mismatch_behavior >= LOG_MISMATCHES);
	int bail_error = (mismatch_behavior >= BAIL_ON_MISMATCH);

	int err = 0;
	if (reg1->eax != reg2->eax) {
		if (print) {
			log_err("eax registers do not match: %s: %lx and %s: %lx\n",
				name1, reg1->eax, name2, reg2->eax);
		}
		err |= 0x1;
	}

	if (reg1->ebx != reg2->ebx) {
		if (print) {
			log_err("ebx registers do not match: %s: %lx and %s: %lx\n",
				name1, reg1->ebx, name2, reg2->ebx);
		}
		err |= 0x2;
	}
	/* check arg2 */
	if (reg1->ecx != reg2->ecx) {
		if (print) {
			log_err("ecx registers do not match: %s: %lx and %s: %lx\n",
				name1, reg1->ecx, name2, reg2->ecx);
		}
		err |= 0x4;
	}
	/* check arg3 */
	if (reg1->edx != reg2->edx) {
		if (print) {
			log_err("edx registers do not match: %s: %lx and %s: %lx\n",
				name1, reg1->edx, name2, reg2->edx);
		}
		err |= 0x8;
	}
	/* check arg4 */
	if (reg1->esi != reg2->esi) {
		if (print) {
			log_err("esi registers do not match: %s: %lx and %s: %lx\n",
				name1, reg1->esi, name2, reg2->esi);
		}
		err |= 0x10;
	}
	/* check arg5 */
	if (reg1->edi != reg2->edi) {
		if (print) {
			log_err("edi registers do not match: %s: %lx and %s: %lx\n",
				name1, reg1->edi, name2, reg2->edi);
		}
		err |= 0x20;
	}
	/* check arg6 */
	if (reg1->ebp != reg2->ebp) {
		if (print) {
			log_err("ebp registers do not match: %s: %lx and %s: %lx\n",
				name1, reg1->ebp, name2, reg2->ebp);
		}
		err |= 0x40;
	}
	/* check eip */
	if (reg1->eip != reg2->eip) {
		if (print) {
			log_err("eip registers do not match: %s: %lx and %s: %lx\n",
				name1, reg1->eip, name2, reg2->eip);
		}
		err = 1;
	}

	/* check eflags, but:
	 * -- ignore CPUID bit (why???)
	 * -- ignore bit 1, since the Linux kernel sometimes reports this as zero
	 * in some states during system calls. It's always 1 during user-space
	 * execution so this shouldn't matter.
	 * */
	long int id_mask = ~((1 << 21) | (1 << 1));
	if ((reg1->eflags & id_mask) != (reg2->eflags & id_mask)) {
		if (print) {
			log_err("eflags registers do not match: %s: 0x%lx and %s: 0x%lx\n",
				name1, reg1->eflags, name2, reg2->eflags);
		}
		err |= 0x80;
	}

	if (bail_error && err) {
		sys_exit();
	}

	return err;
}

void assert_child_regs_are(struct task* t,
			   const struct user_regs_struct* regs,
			   int event, int state)
{
	pid_t tid = t->tid;
	int regs_are_equal;

	read_child_registers(tid, &t->regs);
	regs_are_equal = (0 == compare_register_files("replaying", &t->regs,
						      "recorded", regs,
						      LOG_MISMATCHES));
	if (!regs_are_equal) {
		print_process_mmap(tid);
		assert_exec(t, regs_are_equal,
			    "[%s in state %d, trace file line %d]",
			    strevent(event), state,
			    get_trace_file_lines_counter());
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

static FILE* open_mmap(pid_t tid)
{
	char path[64];
	FILE* file;
	fflush(stdout);
	bzero(path, 64);
	sprintf(path, "/proc/%d/maps", tid);
	if ((file = fopen(path, "r")) == NULL) {
		perror("error reading child memory maps\n");
	}
	return file;
}

void print_process_mmap(pid_t tid)
{
	FILE* file = open_mmap(tid);
	int c = getc(file);
	while (c != EOF) {
		putchar(c);
		c = getc(file);
	}

	if (fclose(file) == EOF) {
		perror("error closing mmap file\n");
	}
}

/**
 * prints a child process memory sections content, according to /proc/pid/maps to the given filename
 */

void print_process_memory(struct task * t, char * filename)
{
	int i;
	pid_t tid = t->tid;

	// open the maps file
	FILE* maps_file = open_mmap(tid);

	// open the output file
	FILE* out_file = (filename) ? fopen(filename,"w") : stderr;

	// flush all files in case we partially record
	flush_trace_files();

	// for each line in the maps file:
	char line[1024];
	void* start;
	void* end;
	char flags[32], binary[128];
	unsigned int dev_minor, dev_major;
	unsigned long long file_offset, inode;
	while ( fgets(line,1024,maps_file) != NULL ) {
		sscanf(line, "%p-%p %31s %Lx %x:%x %Lu %s",
		       &start, &end,
		       flags,
		       &file_offset,
		       &dev_major, &dev_minor,
		       &inode, binary);
		int idx = 0;
		while (isblank(binary[idx])) idx++;
		if (memcmp(binary + idx, "[stack]", sizeof("[stack]") - 1) != 0)
			continue;
		const size_t size = (uintptr_t)end - (uintptr_t)start;
		char * buffer = read_child_data(t, size, start);
		fprintf(out_file,"%s\n", line);
		for (i = 0 ; i < size ; i += 4) {
			unsigned int dword = *((unsigned int *)(buffer + i));
			//fprintf(out_file,"%x | %d %d %d %d | [%x]\n",dword, buffer[i] , buffer[i+1], buffer[i+2], buffer[i+3], start + i);
			fprintf(out_file,"%8x | [%x]\n", dword, (uintptr_t)start + i);
			//fprintf(stderr,"%x",dword);
		}
		sys_free((void**)&buffer);

	}
	fclose(out_file);
	fclose(maps_file);
}

#define CHUNK_SIZE 		(8 * PAGE_SIZE)

int get_memory_size(struct task * t) {
	pid_t tid = t->tid;
	int result = 0;

	// open the maps file
	FILE *maps_file = open_mmap(tid);

	// for each line in the maps file:
	char line[1024];
	void *start, *end;
	char flags[32], binary[128];
	unsigned int dev_minor, dev_major;
	unsigned long long file_offset, inode;
	while ( fgets(line,1024,maps_file) != NULL ) {
		sscanf(line,"%p-%p %31s %Lx %x:%x %Lu %s",
		       &start, &end,
		       flags,
		       &file_offset,
		       &dev_major, &dev_minor,
		       &inode, binary);
		int size = (end - start);
		result += size;
	}
	sys_fclose(maps_file);
	return result;
}

/**
 * checksums all regions of memory
 */
void checksum_process_memory(struct task * t)
{
	pid_t tid = t->tid;
	int i;

	// open the maps file
	FILE *maps_file = open_mmap(tid);

	// flush all files in case we start replaying while still recording
	flush_trace_files();

	// open the checksums file
	char checksums_filename[1024];
	sprintf(checksums_filename,"%s/%d_%d",get_trace_path(),get_global_time(),tid);
	FILE *checksums_file = fopen(checksums_filename,"w");

	// for each line in the maps file:
	char line[1024];
	void *start, *end;
	char flags[32], binary[128];
	unsigned int dev_minor, dev_major;
	unsigned long long file_offset, inode;
	while ( fgets(line,1024,maps_file) != NULL ) {
		sscanf(line,"%p-%p %31s %Lx %x:%x %Lu %s",
		       &start, &end,
		       flags,
		       &file_offset,
		       &dev_major, &dev_minor,
		       &inode, binary);
		/*
		i = 0;
		while (isblank(binary[i])) i++;
		bool dev_zero = FALSE;
		if (memcmp(binary + i, "/dev/zero", sizeof("/dev/zero") - 1) == 0) {
			dev_zero = TRUE;
		}
		*/
		int checksum = 0;
		// read a chunk at a time
		size_t size = end - start, offset = 0;
		while (offset < size) {
			int rest = (size - offset < CHUNK_SIZE) ? size - offset : CHUNK_SIZE;
			char buffer[CHUNK_SIZE];
			checked_pread(t, buffer, rest, (off_t)start + offset);
			for (i = 0 ; i < rest ; i += 4) {
				unsigned int dword = *((unsigned int *)(buffer + i));
				checksum += dword;
			}
			offset += CHUNK_SIZE;
		}
		fprintf(checksums_file,"(%x) %s", checksum, line);
		//printf("%x-%x:%x\n", start, end, checksum);
	}
	sys_fclose(checksums_file);
	sys_fclose(maps_file);
}

void validate_process_memory(struct task * t)
{
	// open the checksums file
	char checksums_filename[1024] = {0};
	sprintf(checksums_filename,"%s/%d_%d",get_trace_path(),t->trace.global_time,t->rec_tid);
	FILE *checksums_file = fopen(checksums_filename,"r");

	// for each line in the checksums file:
	char line[1024];
	void *start, *end;
	int i;
	bool scratch;
	while ( fgets(line,1024,checksums_file) != NULL ) {
		int checksum = 0, rchecksum = 0;
		sscanf(line,"(%x) %p-%p", &rchecksum, &start, &end);

		// check to see if its a scratch memory
		for (i = 0 ; i < scratch_table_size; ++i) {
			if (scratch_table[i] == start) {
				scratch = TRUE;
				break;
			}
		}

		// skip scratch regions
		if (scratch) {
			debug("Skipping scratch %p",start);
			scratch = FALSE;
			continue;
		}

		// read a chunk at a time
		size_t size = end - start, offset = 0;
		while (offset < size) {
			int rest = (size - offset < CHUNK_SIZE) ? size - offset : CHUNK_SIZE;
			char buffer[CHUNK_SIZE];
			checked_pread(t, buffer, rest, (off_t)start + offset);
			for (i = 0 ; i < rest ; i += 4) {
				unsigned int dword = *((unsigned int *)(buffer + i));
				checksum += dword;
			}
			offset += CHUNK_SIZE;
		}
		if (!(checksum == rchecksum)) {
			log_warn("Memory differs on %p", start);
			getchar();
		}
	}

	sys_fclose(checksums_file);
}

void * get_mmaped_region_end(struct task * t, void * mmap_start)
{
	// open the maps file
	FILE *maps_file = open_mmap(t->tid);

	// for each line in the maps file:
	char line[1024];
	void *start, *end, *result = NULL;
	while ( fgets(line,1024,maps_file) != NULL ) {
		sscanf(line,"%p-%p", &start, &end);
		if (start <= mmap_start && mmap_start < end) {
			result = end;
			break;
		}

	}
	sys_fclose(maps_file);
	return result;

}

char * get_mmaped_region_filename(struct task * t, void * mmap_start)
{
	// open the maps file
	FILE *maps_file = open_mmap(t->tid);

	// for each line in the maps file:
	char line[1024] = {0};
	void *start, *end;
	char flags[32], binary[512] = {0}, *result = NULL;
	unsigned int dev_minor, dev_major;
	unsigned long long file_offset, inode;
	while ( fgets(line,1024,maps_file) != NULL ) {
		sscanf(line,"%p-%p %31s %Lx %x:%x %Lu %s",
		       &start, &end,
		       flags,
		       &file_offset,
		       &dev_major, &dev_minor,
		       &inode, binary);
		if (start <= mmap_start && mmap_start < end) {
			// found it
			assert(strlen(binary) > 0);
			size_t index = 0;
			while ( isblank(*binary) ) index++; // clear white characters
			result = sys_malloc_zero(strlen(binary + index) + 1);
			strcpy(result,binary + index);
			break;
		}
	}
	sys_fclose(maps_file);
	assert(result && "unable to locate map end for given address");
	return result;
}


/**
 * This function checks if the specified memory region (start - end) is
 * mapped in the child process.
 * @return 0: if the memory region is not mapped
 * 		   1: if the memory region is mapped
 */
int check_if_mapped(struct task *t, void *start, void *end)
{
	pid_t tid = t->tid;

	FILE* file = open_mmap(tid);
	char buf[256];
	char tmp[9];
	bzero(tmp, 9);

	while (fgets(buf, 256, file)) {
		memcpy(tmp, buf, 8);
		void *mmap_start = (void*) strtoul(tmp, NULL, 16);
		memcpy(tmp, buf + 9, 8);
		void *mmap_end = (void*) strtoul(tmp, NULL, 16);

		if (start >= mmap_start && end <= mmap_end) {
			sys_fclose(file);
			return 1;
		}
	}

	sys_fclose(file);
	return 0;
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

void inject_code(struct current_state_buffer* buf, char* code)
{
	int i;
	long data;

	char tmp_code[buf->code_size]; //inject_patraceme(current_tid);
	//ptrace(PTRACE_SETOPTIONS, current_tid, 0, PTRACE_O_TRACEEXIT | PTRACE_O_TRACECLONE | PTRACE_O_TRACESYSGOOD);

	memset(tmp_code, 0, buf->code_size);
	unsigned long original_start = buf->regs.eip;
	//assure alignment
	int offset = original_start & 0x3;
	memcpy(tmp_code + offset, code, 4);

	for (i = 0; i < buf->code_size / 4; i++) {
		memcpy(&data, tmp_code + i * 4, sizeof(long));
		write_child_code(buf->pid, buf->start_addr + i, data);
	}

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

// returns the eax
int inject_and_execute_syscall(struct task * t, struct user_regs_struct * call_regs) {
	pid_t tid = t->tid;
	struct user_regs_struct orig_regs;
	read_child_registers(tid, &orig_regs);
	void *code = read_child_data(t, 4, (void*)orig_regs.eip);

	// set up the system call
	write_child_registers(tid, call_regs);

	// inject code that executes the additional system call
	char syscall[] = { 0xcd, 0x80 };
	write_child_data(t, 2, (void*)call_regs->eip, syscall);

	sys_ptrace_syscall(tid);
	sys_waitpid(tid, &t->status);

	if (GET_PTRACE_EVENT(t->status) == PTRACE_EVENT_SECCOMP
	    /* XXX this is a special case for ubuntu 12.04.  revisit
	     * this check if an event is added with number 8 (just
	     * after SECCOMP */
	    || GET_PTRACE_EVENT(t->status) == PTRACE_EVENT_SECCOMP_OBSOLETE) {
		sys_ptrace_syscall(tid);
		sys_waitpid(tid, &t->status);
	}

	assert(GET_PTRACE_EVENT(t->status) == 0);

	sys_ptrace_syscall(tid);
	sys_waitpid(tid, &t->status);

	// save the result
	int result = read_child_eax(tid);

	// reset to the original state
	write_child_registers(tid, &orig_regs);
	write_child_data(t, 2, (void*)call_regs->eip, code);
	sys_free(&code);

	return result;
}

void add_scratch(void *ptr, int size) {
	scratch_table[scratch_table_size++] = ptr;
	scratch_overall_size += size;
}

int overall_scratch_size() {
	return scratch_overall_size;
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

int should_copy_mmap_region(const char* filename, struct stat* stat,
			    int prot, int flags)
{
	int can_write_file;

	if ((flags & MAP_PRIVATE) && (prot & PROT_EXEC)) {
		/* We currently don't record the images that we
		 * exec(). Since we're being optimistic there (*cough*
		 * *cough*), we're doing no worse (in theory) by being
		 * optimistic about the shared libraries too, most of
		 * which are system libraries. */
		debug("  (no copy for +x private mapping %s)", filename);
		return 0;
	}
	if (flags & MAP_PRIVATE) {
		/* It's technically undefined whether processes can
		 * observe changes to PRIVATE mappings after the mmap2
		 * call, but in practice they *will* observe changes.
		 * That means that unless the program is fundamentally
		 * buggy, it expects the backing file to be consistent
		 * and unchanged.  So we optimistically assume that
		 * the file is effectively read-only.  (It doesn't
		 * matter whether PROT_WRITE was specified, since
		 * those writes can't propagate to the backing
		 * file.) */
		debug("  (no copy for -x private mapping %s)", filename);
		return 0;
	}

	/* TODO: using "can the euid of the rr process write this
	 * file" as an approximation of whether the tracee can write
	 * the file.  If the tracee is messing around with
	 * set*[gu]id(), the real answer may be different. */
	can_write_file = (0 == access(filename, W_OK));
	if (!can_write_file && 0 == stat->st_uid) {
		/* Shared mapping owned by root: we assume this was
		 * meant to be a PRIVATE mapping, but the program
		 * misspoke.  So we treat it the same way as an
		 * PRIVATE mapping.
		 *
		 * /etc/passwd falls into this class, but the odds of
		 * it being mutated are probably not higher than
		 * system libs being updated.
		 *
		 * XXX what about the fontconfig cache files?*/
		assert(!(prot & PROT_WRITE));
		debug("  (no copy for root-owned ro(?) shared mapping %s)",
		      filename);
		return 0;
	}
	if (!can_write_file) {
		/* mmap'ing another user's (non-system) files?  Highly
		 * irregular ... */
		fatal("Uhandled mmap %s(prot:%x%s); uid:%d mode:%o",
		      filename, prot, (flags & MAP_SHARED) ? ";SHARED" : "",
		      stat->st_uid, stat->st_mode);
	}
	/* Shared mapping that we can write.  Should assume that the
	 * mapping is likely to change. */
	debug("  copy for writeable SHARED mapping %s", filename);
	if (PROT_WRITE | prot) {
		log_warn("%s is SHARED|WRITEABLE; that's not handled correctly yet. Optimistically hoping it's not written.",
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

	/* Start running the syscall. */
	sys_ptrace_syscall(tid);
	if (WAIT == wait) {
		return wait_remote_syscall(t, state);
	}
	return 0;
}

long wait_remote_syscall(struct task* t,
			 struct current_state_buffer* state)
{
	pid_t tid = t->tid;
	/* Wait for syscall-exit trap. */
	sys_waitpid(tid, &t->status);
	return read_child_eax(tid);
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

void* init_syscall_buffer(struct task* t, void* map_hint,
			  int share_desched_fd)
{
	pid_t tid = t->tid;
	char shmem_filename[PATH_MAX];
	struct current_state_buffer state;
	struct sockaddr_un addr;
	long child_ret;
	long child_sockaddr, child_msg;
	void* child_fdptr;
	void* child_args_vec;
	int listen_sock, sock, child_sock;
	int shmem_fd, child_shmem_fd;
	void* map_addr;
	void* child_map_addr;

	/* NB: the tracee can't be interrupted with a signal while
	 * we're processing the rrcall, because it's masked off all
	 * signals. */

	/* Arguments to the rrcall. */
	prepare_remote_syscalls(t, &state);
	t->untraced_syscall_ip = (void*)state.regs.ebx;
	child_sockaddr = state.regs.ecx;
	child_msg = state.regs.edx;
	child_fdptr = (void*)state.regs.esi;
	child_args_vec = (void*)state.regs.edi;

	snprintf(shmem_filename, sizeof(shmem_filename) - 1,
		 "/dev/shm/rr-tracee-shmem-%d", tid);
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
	write_socketcall_args(t, child_args_vec,
			      AF_UNIX, SOCK_STREAM, 0);
	child_sock = remote_syscall2(t, &state, SYS_socketcall,
				     SYS_SOCKET, (uintptr_t)child_args_vec);
	if (0 > child_sock) {
		errno = -child_sock;
		fatal("Failed to create child socket");
	}
	write_socketcall_args(t, child_args_vec,
			      child_sock, child_sockaddr, sizeof(addr));
	remote_syscall(t, &state, DONT_WAIT, SYS_socketcall,
		       SYS_CONNECT, (uintptr_t)child_args_vec, 0, 0, 0, 0);
	/* Now the child is waiting for us to accept it. */

	/* Accept the child's connection and finish its syscall.
	 *
	 * XXX could be really anal and check credentials of
	 * connecting endpoint ... */
	sock = accept(listen_sock, NULL, NULL);
	if ((child_ret = wait_remote_syscall(t, &state))) {
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
		write_socketcall_args(t, child_args_vec,
				      child_sock, child_msg, 0);
		remote_syscall(t, &state, DONT_WAIT, SYS_socketcall,
			       SYS_SENDMSG, (uintptr_t)child_args_vec,
			       0, 0, 0, 0);
		/* Child may be waiting on our recvmsg(). */

		/* Read the shared fd and finish the child's syscall. */
		t->desched_fd = recv_fd(sock, &t->desched_fd_child);
		if (0 >= wait_remote_syscall(t, &state)) {
			errno = -child_ret;
			fatal("Failed to sendmsg() in tracee");
		}
	} else {
		t->desched_fd_child = REPLAY_DESCHED_EVENT_FD;
	}

	/* Share the shmem fd with the child.  It's ok to reuse the
	 * |child_msg| buffer. */
	send_fd(shmem_fd, sock);
	write_socketcall_args(t, child_args_vec,
			      child_sock, child_msg, 0);
	child_ret = remote_syscall2(t, &state, SYS_socketcall,
				    SYS_RECVMSG, (uintptr_t)child_args_vec);
	if (0 >= child_ret) {
		errno = -child_ret;
		fatal("Failed to recvmsg() shared fd in tracee");
	}

	/* Get the newly-allocated fd. */
	child_shmem_fd = read_child_data_word(tid, child_fdptr);

	/* Write zero over the shared fd number, which since it's a
	 * "real" fd, may not be the same across record/replay owing
	 * to emulated fds. */
	write_child_data_word(tid, child_fdptr, 0);

	/* Socket magic is now done. */
	close(listen_sock);
	close(sock);
	remote_syscall1(t, &state, SYS_close, child_sock);

	/* Map the segment in our address space and in the
	 * tracee's. */
	if ((void*)-1 ==
	    (map_addr = mmap(NULL, SYSCALLBUF_BUFFER_SIZE,
			     PROT_READ | PROT_WRITE, MAP_SHARED,
			     shmem_fd, 0))) {
		fatal("Failed to mmap shmem region");
	}
	child_map_addr = (void*)remote_syscall6(t, &state, SYS_mmap2,
						(uintptr_t)map_hint,
						SYSCALLBUF_BUFFER_SIZE,
						PROT_READ | PROT_WRITE,
						MAP_SHARED, child_shmem_fd, 0);

	t->syscallbuf_child = child_map_addr;
	t->syscallbuf_hdr = map_addr;
	/* No entries to begin with. */
	memset(t->syscallbuf_hdr, 0, sizeof(*t->syscallbuf_hdr));

	close(shmem_fd);
	remote_syscall1(t, &state, SYS_close, child_shmem_fd);

	/* Return the mapped address to the child. */
	state.regs.eax = (uintptr_t)child_map_addr;
	finish_remote_syscalls(t, &state);

	return child_map_addr;
}
