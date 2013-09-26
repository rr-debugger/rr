/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

//#define DEBUGTAG "Replayer"

#define _GNU_SOURCE

#include "replayer.h"

#include <assert.h>
#include <err.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <netinet/in.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/personality.h>
#include <sys/poll.h>
#include <sys/ptrace.h>
#include <asm/ptrace-abi.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/user.h>
#include <unistd.h>

#include "dbg_gdb.h"
#include "rep_sched.h"
#include "rep_process_event.h"

#include "../external/tree.h"
#include "../share/dbg.h"
#include "../share/hpc.h"
#include "../share/trace.h"
#include "../share/ipc.h"
#include "../share/sys.h"
#include "../share/task.h"
#include "../share/util.h"
#include "../share/syscall_buffer.h"

#include <perfmon/pfmlib_perf_event.h>

#define SKID_SIZE 55

typedef enum { TRAP_NONE = 0, TRAP_STEPI,
	       TRAP_BKPT_INTERNAL, TRAP_BKPT_USER } trap_t;

struct breakpoint {
	void* addr;
	/* "Refcounts" of breakpoints set at |addr|.  The breakpoint
	 * object must be unique since we have to save the overwritten
	 * data, and we can't enforce the order in which breakpoints
	 * are set/removed. */
	int internal_count, user_count;
	byte overwritten_data;
	RB_ENTRY(breakpoint) entry;
};

static const struct dbg_request continue_all_tasks = {
	.type = DREQ_CONTINUE,
	.target = -1,
	.mem = { 0 },
	.reg = 0
};

static RB_HEAD(breakpoint_tree, breakpoint) breakpoints =
	RB_INITIALIZER(&breakpoints);

static const byte int_3_insn = 0xCC;

/* Nonzero after the first exec() has been observed during replay.
 * After this point, the first recorded binary image has been exec()d
 * over the initial rr image. */
static bool validate = FALSE;

RB_PROTOTYPE_STATIC(breakpoint_tree, breakpoint, entry, breakpoint_cmp)

static void debug_memory(struct task* t)
{
	/* dump memory as user requested */
	if (rr_flags()->dump_on == t->trace.stop_reason
	    || rr_flags()->dump_on == DUMP_ON_ALL
	    || rr_flags()->dump_at == t->trace.global_time) {
		char pid_str[PATH_MAX];
		snprintf(pid_str, sizeof(pid_str) - 1, "%s/%d_%d_rep",
			 get_trace_path(),
			 t->tid, t->trace.global_time);
		print_process_memory(t, pid_str);
	}

	/* check memory checksum */
	if (validate
	    && ((rr_flags()->checksum == CHECKSUM_ALL)
		|| (rr_flags()->checksum == CHECKSUM_SYSCALL
		    && t->trace.state == STATE_SYSCALL_EXIT)
		|| (rr_flags()->checksum <= t->trace.global_time))) {
		validate_process_memory(t);
	}
}

static void replay_init_scratch_memory(struct task* t,
				       struct mmapped_file *file)
{
    /* initialize the scratchpad as the recorder did, but
     * make it PROT_NONE. The idea is just to reserve the
     * address space so the replayed process address map
     * looks like the recorded process, if it were to be
     * probed by madvise or some other means. But we make
     * it PROT_NONE so that rogue reads/writes to the
     * scratch memory are caught.
     */

    /* set up the mmap system call */
    struct user_regs_struct orig_regs;
    read_child_registers(t->tid, &orig_regs);

    struct user_regs_struct mmap_call = orig_regs;

    mmap_call.eax = SYS_mmap2;
    mmap_call.ebx = (uintptr_t)file->start;
    mmap_call.ecx = file->end - file->start;
    mmap_call.edx = PROT_NONE;
    mmap_call.esi = MAP_PRIVATE | MAP_ANONYMOUS;
    mmap_call.edi = -1;
    mmap_call.ebp = 0;

    inject_and_execute_syscall(t,&mmap_call);

    write_child_registers(t->tid,&orig_regs);
}

/**
 * Return the value of |reg| in |regs|, or set |*defined = 0| and
 * return an undefined value if |reg| isn't found.
 */
static long get_reg(const struct user_regs_struct* regs, dbg_register reg,
		    int* defined)
{
	*defined = 1;
	switch (reg) {
	case DREG_EAX: return regs->eax;
	case DREG_ECX: return regs->ecx;
	case DREG_EDX: return regs->edx;
	case DREG_EBX: return regs->ebx;
	case DREG_ESP: return regs->esp;
	case DREG_EBP: return regs->ebp;
	case DREG_ESI: return regs->esi;
	case DREG_EDI: return regs->edi;
	case DREG_EIP: return regs->eip;
	case DREG_EFLAGS: return regs->eflags;
	case DREG_CS: return regs->xcs;
	case DREG_SS: return regs->xss;
	case DREG_DS: return regs->xds;
	case DREG_ES: return regs->xes;
	case DREG_FS: return regs->xfs;
	case DREG_GS: return regs->xgs;
	case DREG_ORIG_EAX: return regs->orig_eax;
	default:
		*defined = 0;
		return 0;
	}
}

static dbg_threadid_t get_threadid(struct task* t)
{
	dbg_threadid_t thread = t->rec_tid;
	return thread;
}

static byte* read_mem(struct task* t, void* addr, size_t len,
		      size_t* read_len)
{
	ssize_t nread;
	void* buf = read_child_data_checked(t, len, addr, &nread);
	*read_len = MAX(0, nread);
	return buf;
}

static int* breakpoint_counter(struct breakpoint* bp, trap_t which)
{
	int* counter = TRAP_BKPT_USER == which ?
		       &bp->user_count : &bp->internal_count;
	assert(TRAP_BKPT_INTERNAL == which || TRAP_BKPT_USER == which);
	assert(*counter >= 0);
	return counter;
}

static void add_breakpoint(struct breakpoint* bp)
{
	RB_INSERT(breakpoint_tree, &breakpoints, bp);
}

static void erase_breakpoint(struct breakpoint* bp)
{
	RB_REMOVE(breakpoint_tree, &breakpoints, bp);
}

static void ref_breakpoint(struct breakpoint* bp, trap_t which)
{
	++*breakpoint_counter(bp, which);
}

static int unref_breakpoint(struct breakpoint* bp, trap_t which)
{
	--*breakpoint_counter(bp, which);
	assert(bp->internal_count >= 0 && bp->user_count >= 0);
	return bp->internal_count + bp->user_count;
}

static struct breakpoint* find_breakpoint(void* addr)
{
	struct breakpoint search = { .addr = addr };
	return RB_FIND(breakpoint_tree, &breakpoints, &search);
}

static void set_sw_breakpoint(struct task* t, void* ip, trap_t type)
{
	struct breakpoint* bp = find_breakpoint(ip);
	if (!bp) {
		byte* orig_data_ptr;

		bp = sys_malloc_zero(sizeof(*bp));
		bp->addr = ip;

		orig_data_ptr = read_child_data(t, sizeof(int_3_insn),
						bp->addr);
		memcpy(&bp->overwritten_data, orig_data_ptr,
		       sizeof(int_3_insn));
		sys_free((void**)&orig_data_ptr);

		write_child_data_n(t->tid,
				   sizeof(int_3_insn), bp->addr, &int_3_insn);
		add_breakpoint(bp);
	}
	ref_breakpoint(bp, type);
}

static void remove_sw_breakpoint(struct task* t, void* ip, trap_t type)
{
	struct breakpoint* bp = find_breakpoint(ip);
	if (bp && 0 == unref_breakpoint(bp, type)) {
		write_child_data_n(t->tid,
				   sizeof(bp->overwritten_data), bp->addr,
				   &bp->overwritten_data);
		erase_breakpoint(bp);
		sys_free((void**)&bp);
	}
}

static void remove_internal_sw_breakpoint(struct task* t, void* ip)
{
	remove_sw_breakpoint(t, ip, TRAP_BKPT_INTERNAL);
}

static void remove_user_sw_breakpoint(struct task* t,
				      const struct dbg_request* req)
{
	assert(sizeof(int_3_insn) == req->mem.len);
	remove_sw_breakpoint(t, req->mem.addr, TRAP_BKPT_USER);
}

static void set_internal_sw_breakpoint(struct task* t, void* ip)
{
	set_sw_breakpoint(t, ip, TRAP_BKPT_INTERNAL);
}

static void set_user_sw_breakpoint(struct task* t,
				   const struct dbg_request* req)
{
	assert(sizeof(int_3_insn) == req->mem.len);
	set_sw_breakpoint(t, req->mem.addr, TRAP_BKPT_USER);
}

static trap_t ip_breakpoint_type(void* eip)
{
	void* ip = (void*)((uintptr_t)eip - sizeof(int_3_insn));
	struct breakpoint* bp = find_breakpoint(ip);
	/* NB: USER breakpoints need to be processed before INTERNAL
	 * ones.  We want to give the debugger a chance to dispatch
	 * commands before we attend to the internal rr business.  So
	 * if there's a USER "ref" on the breakpoint, treat it as a
	 * USER breakpoint. */
	return (!bp ? TRAP_NONE :
		(0 < *breakpoint_counter(bp, TRAP_BKPT_USER) ?
		 TRAP_BKPT_USER : TRAP_BKPT_INTERNAL));
}

/**
 * Reply to debugger requests until the debugger asks us to resume
 * execution.
 */
static struct dbg_request process_debugger_requests(struct dbg_context* dbg,
						    struct task* t)
{
	if (!dbg) {
		return continue_all_tasks;
	}
	while (1) {
		struct dbg_request req = dbg_get_request(dbg);
		struct task* target = NULL;

		if (dbg_is_resume_request(&req)) {
			return req;
		}

		/* These requests don't require a target task. */
		switch (req.type) {
		case DREQ_GET_CURRENT_THREAD:
			dbg_reply_get_current_thread(dbg, get_threadid(t));
			continue;
		case DREQ_GET_OFFSETS:
			/* TODO */
			dbg_reply_get_offsets(dbg);
			continue;
		case DREQ_GET_THREAD_LIST: {
			pid_t* tids;
			size_t len;
			rep_sched_enumerate_tasks(&tids, &len);
			dbg_reply_get_thread_list(dbg, tids, len);
			sys_free((void**)&tids);
			continue;
		}
		case DREQ_INTERRUPT:
			/* Tell the debugger we stopped and await
			 * further instructions. */
			dbg_notify_stop(dbg, get_threadid(t), 0);
			continue;
		default:
			/* fall through to next switch stmt */
			break;
		}

		target = (req.target > 0) ?
			 rep_sched_lookup_thread(req.target) : t;
		/* These requests query or manipulate which task is
		 * the target, so it's OK if the task doesn't
		 * exist. */
		switch (req.type) {
		case DREQ_GET_IS_THREAD_ALIVE:
			dbg_reply_get_is_thread_alive(dbg, !!target);
			continue;
		case DREQ_SET_CONTINUE_THREAD:
		case DREQ_SET_QUERY_THREAD:
			dbg_reply_select_thread(dbg, !!target);
			continue;
		default:
			/* fall through to next switch stmt */
			break;
		}

		/* These requests require a valid target task.  We
		 * trust gdb to use the information provided above to
		 * only query valid tasks. */
		switch (req.type) {
		case DREQ_GET_MEM: {
			size_t len;
			byte* mem = read_mem(target, req.mem.addr, req.mem.len,
					     &len);
			dbg_reply_get_mem(dbg, mem, len);
			sys_free((void**)&mem);
			continue;
		}
		case DREQ_GET_REG: {
			struct user_regs_struct regs;
			dbg_regvalue_t val;

			read_child_registers(target->tid, &regs);
			val.value = get_reg(&regs, req.reg, &val.defined);
			dbg_reply_get_reg(dbg, val);
			continue;
		}
		case DREQ_GET_REGS: {
			struct user_regs_struct regs;
			struct dbg_regfile file;
			int i;
			dbg_regvalue_t* val;

			read_child_registers(target->tid, &regs);
			memset(&file, 0, sizeof(file));
			for (i = DREG_EAX; i < DREG_NUM_USER_REGS; ++i) {
				val = &file.regs[i];
				val->value = get_reg(&regs, i, &val->defined);
			}
			val = &file.regs[DREG_ORIG_EAX];
			val->value = get_reg(&regs, DREG_ORIG_EAX,
					     &val->defined);

			dbg_reply_get_regs(dbg, &file);
			continue;
		}
		case DREQ_GET_STOP_REASON: {
			dbg_reply_get_stop_reason(dbg, target->rec_tid,
						  target->child_sig);
			continue;
		}
		case DREQ_SET_SW_BREAK:
			set_user_sw_breakpoint(target, &req);
			dbg_reply_watchpoint_request(dbg, 0);
			continue;
		case DREQ_REMOVE_SW_BREAK:
			remove_user_sw_breakpoint(target, &req);
			dbg_reply_watchpoint_request(dbg, 0);
			break;
		case DREQ_REMOVE_HW_BREAK:
		case DREQ_REMOVE_RD_WATCH:
		case DREQ_REMOVE_WR_WATCH:
		case DREQ_REMOVE_RDWR_WATCH:
		case DREQ_SET_HW_BREAK:
		case DREQ_SET_RD_WATCH:
		case DREQ_SET_WR_WATCH:
		case DREQ_SET_RDWR_WATCH:
			dbg_reply_watchpoint_request(dbg, -1);
			continue;
		default:
			fatal("Unknown debugger request %d", req.type);
		}
	}
}

/**
 * Compares the register file as it appeared in the recording phase
 * with the current register file.
 */
static void validate_args(int event, int state, struct task* t)
{
	struct user_regs_struct* rec_regs = &t->trace.recorded_regs;

	/* don't validate anything before execve is done as the actual
	 * process did not start prior to this point */
	if (!validate) {
		return;
	}
	if ((SYS_pwrite64 == event || SYS_pread64 == event)
	    && STATE_SYSCALL_EXIT == state) {
		struct user_regs_struct cur_regs;
		/* The x86 linux 3.5.0-36 kernel packaged with Ubuntu
		 * 12.04 has been observed to mutate $esi across
		 * syscall entry/exit.  (This has been verified
		 * outside of rr as well; not an rr bug.)  It's not
		 * clear whether this is a ptrace bug or a kernel bug,
		 * but either way it's not supposed to happen.  So we
		 * fudge registers here to cover up that bug. */
		read_child_registers(t->tid, &cur_regs);
		if (cur_regs.esi != rec_regs->esi) {
			log_warn("Probably saw kernel bug mutating $esi across pread/write64 call: recorded:0x%lx; replaying:0x%lx.  Fudging registers.",
				 rec_regs->esi, cur_regs.esi);
			rec_regs->esi = cur_regs.esi;
		}
	}
	assert_child_regs_are(t, rec_regs, event, state);
}

/**
 * Continue until reaching either the "entry" of an emulated syscall,
 * or the entry or exit of an executed syscall.  |emu| is nonzero when
 * we're emulating the syscall.  Return 0 when the next syscall
 * boundary is reached, or nonzero if advancing to the boundary was
 * interrupted by an unknown trap.
 */
enum { EXEC = 0, EMU = 1 };
static int cont_syscall_boundary(struct task* t, int emu, int stepi)
{
	pid_t tid = t->tid;

	if (emu && stepi) {
		sys_ptrace_sysemu_singlestep(tid);
	} else if (emu) {
		sys_ptrace_sysemu(tid);
	} else if (stepi) {
		sys_ptrace_singlestep(tid);
	} else {
		sys_ptrace_syscall(tid);
	}
	sys_waitpid(tid, &t->status);

	switch ((t->child_sig = signal_pending(t->status))) {
	case 0:
		break;
	case SIGCHLD:
		/* SIGCHLD is pending, do not deliver it, wait for it
		 * to appear in the trace SIGCHLD is the only signal
		 * that should ever be generated as all other signals
		 * are emulated! */
		return cont_syscall_boundary(t, emu, stepi);
	case SIGTRAP:
		return 1;
	default:
		assert_exec(t, 0, "Replay got unrecorded signal %d",
			    t->child_sig);
	}

	assert(t->child_sig == 0);

	return 0;
}

/**
 *  Step over the system call instruction to "exit" the emulated
 *  syscall.
 *
 * XXX verify that this can't be interrupted by a breakpoint trap
 */
static void step_exit_syscall_emu(struct task *t)
{
	pid_t tid = t->tid;
	struct user_regs_struct regs;

	read_child_registers(tid, &regs);

	sys_ptrace_sysemu_singlestep(tid);
	sys_waitpid(tid, &t->status);

	write_child_registers(tid, &regs);

	t->status = 0;
}

/**
 * Advance to the next syscall entry (or virtual entry) according to
 * |step|.  Return 0 if successful, or nonzero if an unhandled trap
 * occurred.
 */
static int enter_syscall(struct task* t,
			 const struct rep_trace_step* step,
			 int stepi)
{
	int ret;
	if ((ret = cont_syscall_boundary(t, step->syscall.emu, stepi))) {
		return ret;
	}
	validate_args(step->syscall.no, STATE_SYSCALL_ENTRY, t);
	return ret;
}

/**
 * Advance past the reti (or virtual reti) according to |step|.
 * Return 0 if successful, or nonzero if an unhandled trap occurred.
 */
static int exit_syscall(struct task* t,
			const struct rep_trace_step* step,
			int stepi)
{
	int i, emu = step->syscall.emu;

	if (!emu) {
		int ret = cont_syscall_boundary(t, emu, stepi);
		if (ret) {
			return ret;
		}
	}

	for (i = 0; i < step->syscall.num_emu_args; ++i) {
		set_child_data(t);
	}
	if (step->syscall.emu_ret) {
		set_return_value(t);
	}
	validate_args(step->syscall.no, STATE_SYSCALL_EXIT, t);

	if (emu) {
		step_exit_syscall_emu(t);
	}
	return 0;
}

/**
 * Advance |t| to the next signal or trap.  If |stepi| is |STEPI|,
 * then execution resumes by single-stepping.  Otherwise it continues
 * normally.  The delivered signal is recorded in |t->child_sig|.
 */
enum { DONT_STEPI = 0, STEPI };
static void continue_or_step(struct task* t, int stepi)
{
	pid_t tid = t->tid;
	int child_sig_gt_zero;

	if (stepi) {
		sys_ptrace_singlestep(tid);
	} else {
		/* We continue with PTRACE_SYSCALL for error checking:
		 * since the next event is supposed to be a signal,
		 * entering a syscall here means divergence.  There
		 * shouldn't be any straight-line execution overhead
		 * for SYSCALL vs. CONT, so the difference in cost
		 * should be neglible. */
		sys_ptrace_syscall(tid);
	}
	sys_waitpid(tid, &t->status);

	t->child_sig = signal_pending(t->status);

	/* TODO: get rid of this if-stmt after we always read
	 * registers following an execution resume/waitpid. */
	child_sig_gt_zero = (0 < t->child_sig);
	if (child_sig_gt_zero) {
		return;
	}
	read_child_registers(t->tid, &t->regs);
	assert_exec(t, child_sig_gt_zero,
		    "Replaying `%s' (line %d): expecting tracee signal or trap, but instead at `%s' (rcb: %" PRIu64 ")",
		    strevent(t->trace.stop_reason),
		    get_trace_file_lines_counter(),
		    strevent(t->regs.orig_eax), read_rbc(t->hpc));
}

/**
 * Return nonzero if |t| was stopped for a breakpoint trap (int3),
 * as opposed to a trace trap.  Return zero in the latter case.
 */
static int is_breakpoint_trap(struct task* t)
{
	siginfo_t si;

	assert(SIGTRAP == t->child_sig);

	sys_ptrace_getsiginfo(t->tid, &si);
	assert(SIGTRAP == si.si_signo);

	/* XXX unable to find docs on which of these "should" be
	 * right.  The SI_KERNEL code is seen in the int3 test, so we
	 * at least need to handle that. */
	return SI_KERNEL == si.si_code || TRAP_BRKPT == si.si_code;
}

/**
 * Return one of the (non-zero) enumerated TRAP_* debugger-trap types
 * above if the SIGTRAP generated by the child is intended for the
 * debugger, or zero if it's meant for rr internally.
 *
 * NB: calling this function while advancing the rbc through hpc
 * interrupts when emulating asynchronous signal delivery *will*
 * result in bad results.  Don't call this function from there; it's
 * not necessary.
 */
typedef enum { ASYNC, DETERMINISTIC } sigdelivery_t;
typedef enum { UNKNOWN, NOT_AT_TARGET, AT_TARGET } execstate_t;
static trap_t compute_trap_type(struct task* t, int target_sig,
				sigdelivery_t delivery, execstate_t exec_state,
				int stepi)
{
	struct user_regs_struct regs;
	void* ip;
	trap_t trap_type;

	assert(SIGTRAP == t->child_sig);

	/* We're not replaying a trap, and it was clearly raised on
	 * behalf of the debugger.  (The debugger will verify
	 * that.) */
	if (SIGTRAP != target_sig
	    /* Replay of deterministic signals never internally
	     * single-steps or sets internal breakpoints. */
	    && (DETERMINISTIC == delivery
		/* Replay of async signals will sometimes internally
		 * single-step when advancing to an execution target,
		 * so the trap was only clearly for the debugger if
		 * the debugger was requesting single-stepping. */
		|| (stepi && NOT_AT_TARGET == exec_state))) {
		return stepi ? TRAP_STEPI : TRAP_BKPT_USER;
	}

	/* We're trying to replay a deterministic SIGTRAP, or we're
	 * replaying an async signal. */

	read_child_registers(t->tid, &regs);
	ip = (void*)regs.eip;
	trap_type = ip_breakpoint_type(ip);
	if (TRAP_BKPT_USER == trap_type || TRAP_BKPT_INTERNAL == trap_type) {
		assert(is_breakpoint_trap(t));
		return trap_type;
	}

	if (is_breakpoint_trap(t)) {
		/* We successfully replayed a recorded deterministic
		 * SIGTRAP.  (Because it must have been raised by an
		 * |int3|, but not one we injected.)  Not for the
		 * debugger, although we'll end up notifying it
		 * anyway. */
		assert(DETERMINISTIC == delivery);
		return TRAP_NONE;
	}

	if (DETERMINISTIC == delivery) {
		/* If the delivery of SIGTRAP is supposed to be
		 * deterministic and we didn't just retire an |int 3|
		 * and this wasn't a breakpoint, we must have been
		 * single stepping.  So definitely for the
		 * debugger. */
		assert(stepi);
		return 1;
	}

	/* We're replaying an async signal. */

	if (AT_TARGET == exec_state) {
		/* If we're at the target of the async signal
		 * delivery, prefer delivering the signal to retiring
		 * a possible debugger single-step; we'll notify the
		 * debugger anyway. */
		return TRAP_NONE;
	}

	/* Otherwise, we're not at the execution target, so may have
	 * been internally single-stepping.  We'll notify the debugger
	 * if it was also requesting single-stepping.  The debugger
	 * won't care about the rr-internal trap if it wasn't
	 * requesting single-stepping. */
	return stepi ? TRAP_STEPI : TRAP_NONE;
}

/**
 * Shortcut for callers that don't care about internal breakpoints.
 * Return nonzero if |t|'s trap is for the debugger, zero otherwise.
 */
static int is_debugger_trap(struct task* t, int target_sig,
			    sigdelivery_t delivery, execstate_t exec_state,
			    int stepi)
{
	trap_t type = compute_trap_type(t, target_sig, delivery, exec_state,
					stepi);
	assert(TRAP_BKPT_INTERNAL != type);
	return TRAP_NONE != type;
}

static void guard_overshoot(struct task* t,
			    int64_t target, int64_t remaining)
{
	assert_exec(t, remaining >= 0,
		    "Replay diverged: overshot target rcb=%" PRId64 " by %" PRId64 "\n"
		    "    replaying trace line %d",
		    target, -remaining, get_trace_file_lines_counter());
}

static void guard_unexpected_signal(struct task* t)
{
	int event;
	int child_sig_is_zero_or_sigtrap = (0 == t->child_sig
					    || SIGTRAP == t->child_sig);
	/* "0" normally means "syscall", but continue_or_step() guards
	 * against unexpected syscalls.  So the caller must have set
	 * "0" intentionally. */
	if (child_sig_is_zero_or_sigtrap) {
		return;
	}
	if (t->child_sig) {
		event = -t->child_sig;
	} else {
		read_child_registers(t->tid, &t->regs);
		event = MAX(0, t->regs.orig_eax);
	}
	assert_exec(t, child_sig_is_zero_or_sigtrap,
		    "Replay got unrecorded event %s while awaiting signal\n"
		    "    replaying trace line %d",
		    strevent(event), get_trace_file_lines_counter());
}

static int is_same_execution_point(const struct user_regs_struct* rec_regs,
				   int64_t rcbs_left,
				   const struct user_regs_struct* rep_regs)
{
	return (0 == rcbs_left
		&& 0 == compare_register_files("rep interrupt", rep_regs,
					       "rec", rec_regs,
					       EXPECT_MISMATCHES));
}

/**
 * Run execution forwards for |t| until |*rcb| is reached, and the $ip
 * reaches the recorded $ip.  Return 0 if successful or 1 if an
 * unhandled interrupt occurred.  |sig| is the pending signal to be
 * delivered; it's only used to distinguish debugger-related traps
 * from traps related to replaying execution.  |rcb| is an inout param
 * that will be decremented by branches retired during this attempted
 * step.
 */
static int advance_to(struct task* t, const struct user_regs_struct* regs,
		      int sig, int stepi, int64_t* rcb)
{
	pid_t tid = t->tid;
	void* ip = (void*)regs->eip;
	int64_t rcbs_left;

	assert(t->hpc->rbc.fd > 0);
	assert(t->child_sig == 0);

	/* Step 1: advance to the target rcb (minus a slack region) as
	 * quickly as possible by programming the hpc. */
	rcbs_left = *rcb - read_rbc(t->hpc);

	debug("advancing %" PRId64 " rcbs to reach %" PRId64 "/%p",
	      rcbs_left, *rcb, ip);

	/* XXX should we only do this if (rcb > 10000)? */
	while (rcbs_left - SKID_SIZE > SKID_SIZE) {
		if (SIGTRAP == t->child_sig) {
			/* We proved we're not at the execution
			 * target, and we haven't set any internal
			 * breakpoints, and we're not temporarily
			 * internally single-stepping, so we must have
			 * hit a debugger breakpoint or the debugger
			 * was single-stepping the tracee.  (The
			 * debugging code will verify that.) */
			return 1;
		}
		t->child_sig = 0;

		debug("  programming interrupt for %" PRId64 " rcbs",
		      rcbs_left - SKID_SIZE);
		*rcb -= read_rbc(t->hpc);
		reset_hpc(t, rcbs_left - SKID_SIZE);

		continue_or_step(t, stepi);
		if (HPC_TIME_SLICE_SIGNAL == t->child_sig
		    || SIGCHLD == t->child_sig) {
			/* Tracees can receive SIGCHLD at pretty much
			 * any time during replay.  If we recorded
			 * delivery, we'll manually replay it
			 * eventually (or already have).  Just ignore
			 * here. */
			t->child_sig = 0;
		}
		guard_unexpected_signal(t);

		/* TODO this assertion won't catch many spurious
		 * signals; should assert that the siginfo says the
		 * source is io-ready and the fd is the child's fd. */
		if (fcntl(t->hpc->rbc.fd, F_GETOWN) != tid) {
			fatal("Scheduled task %d doesn't own hpc; replay divergence", tid);
		}

		rcbs_left = *rcb - read_rbc(t->hpc);
	}
	guard_overshoot(t, *rcb, rcbs_left);

	/* Step 2: more slowly, find our way to the target rcb and
	 * execution point.  We set an internal breakpoint on the
	 * target $ip and then resume execution.  When that *internal*
	 * breakpoint is hit (i.e., not one incidentally also set on
	 * that $ip by the debugger), we check again if we're at the
	 * target rcb and execution point.  If not, we temporarily
	 * remove the breakpoint, single-step over the insn, and
	 * repeat.
	 *
	 * What we really want to do is set a (precise)
	 * retired-instruction interrupt and do away with all this
	 * cruft. */
	while (rcbs_left >= 0) {
		/* Invariants here are
		 *  o rcbs_left is up-to-date
		 *  o rcbs_left >= 0
		 *
		 * Possible state of the execution of |t|
		 *  0. at a debugger trap (breakpoint or stepi)
		 *  1. at an internal breakpoint
		 *  2. at the execution target
		 *  3. not at the execution target, but incidentally
		 *     at the target $ip
		 *  4. otherwise not at the execution target
		 *
		 * Determining whether we're at a debugger trap is
		 * surprisingly complicated, but we delegate the work
		 * to |compute_debugger_trap()|.  The rest can be
		 * straightforwardly computed with rbc value and
		 * registers. */
		struct user_regs_struct regs_now;
		int at_target;

		read_child_registers(tid, &regs_now);
		at_target = is_same_execution_point(regs,
						    rcbs_left, &regs_now);
		if (SIGTRAP == t->child_sig) {
			trap_t trap_type = compute_trap_type(
				t, ASYNC, sig,
				at_target ? AT_TARGET : NOT_AT_TARGET,
				stepi);
			switch (trap_type) {
			case TRAP_BKPT_USER:
			case TRAP_STEPI:
				/* Case (0) above: interrupt for the
				 * debugger. */
				debug("    trap was debugger interrupt %d",
				      trap_type);
				return 1;
			case TRAP_BKPT_INTERNAL:
				/* Case (1) above: cover the tracks of
				 * our internal breakpoint, and go
				 * check again if we're at the
				 * target. */
				debug("    trap was for target $ip");
				/* (The breakpoint would have trapped
				 * at the $ip one byte beyond the
				 * target.) */
				assert(!at_target);

				t->child_sig = 0;
				regs_now.eip -= sizeof(int_3_insn);
				write_child_registers(tid, &regs_now);
				/* We just backed up the $ip, but
				 * rewound it over an |int $3|
				 * instruction, which couldn't have
				 * retired a branch.  So we don't need
				 * to adjust |rcb_now|. */
				continue;
			case TRAP_NONE:
				/* Otherwise, we must have been forced
				 * to single-step because the tracee's
				 * $ip was incidentally the same as
				 * the target.  Unfortunately, it's
				 * awkward to assert that here, so we
				 * don't yet.  TODO. */
				debug("    (SIGTRAP but no trap)");
				assert(!stepi);
				t->child_sig = 0;
				break;
			}
		}
		/* We had to keep the internal breakpoint set (if it
		 * was when we entered the loop) for the checks above.
		 * But now we're either done (at the target) or about
		 * to resume execution in one of a variety of ways,
		 * and it's simpler to start out knowing that the
		 * breakpoint isn't set. */
		remove_internal_sw_breakpoint(t, ip);

		if (at_target) {
			/* Case (2) above: done. */
			return 0;
		}

		/* At this point, we've proven that we're not at the
		 * target execution point, and we've ensured the
		 * internal breakpoint is unset. */
		debug("  retiring %" PRId64 " branches to reach %" PRId64,
		      rcbs_left, *rcb);

		if (regs->eip != regs_now.eip) {
			/* Case (4) above: set a breakpoint on the
			 * target $ip and PTRACE_CONT in an attempt to
			 * execute as many non-trapped insns as we
			 * can.  (Unless the debugger is stepping, of
			 * course.)  Trapping and checking
			 * are-we-at-target is slow.  It bears
			 * repeating that the ideal implementation
			 * would be programming a precise counter
			 * interrupt (insns-retired best of all), but
			 * we're forced to be conservative by observed
			 * imprecise counters.  This should still be
			 * no slower than single-stepping our way to
			 * the target execution point. */
			debug("    breaking on target $ip");
			set_internal_sw_breakpoint(t, ip);
			continue_or_step(t, stepi);
		} else {
			/* Case (3) above: we can't put a breakpoint
			 * on the $ip, because resuming execution
			 * would just trap and we'd be back where we
			 * started.  Single-step past it. */
			debug("    (single-stepping over target $ip)");
			continue_or_step(t, STEPI);
		}

		if (HPC_TIME_SLICE_SIGNAL == t->child_sig
		    || SIGCHLD == t->child_sig) {
			/* See the long comment in "Step 1" above.
			 *
			 * We don't usually expect a time-slice signal
			 * during this phase, but it's possible for a
			 * SIGCHLD to interrupt the previous step just
			 * as the tracee enters the slack region,
			 * i.e., where an rbc signal was just about to
			 * fire.  (There's not really a non-racy way
			 * to disable the rbc interrupt, and we need
			 * to keep the counter running for overshoot
			 * checking anyway.)  So this is the most
			 * convenient way to squelch that "spurious"
			 * signal. */
			t->child_sig = 0;
		}
		guard_unexpected_signal(t);

		/* Maintain the "'rcbs_left'-is-up-to-date"
		 * invariant. */
		rcbs_left = *rcb - read_rbc(t->hpc);
	}
	guard_overshoot(t, *rcb, rcbs_left);

	return 0;
}

static void emulate_signal_delivery()
{
	/* We are now at the exact point in the child where the signal
	 * was recorded, emulate it using the next trace line (records
	 * the state at sighandler entry). */
	struct task* t = rep_sched_get_thread();
	pid_t tid = t->tid;
	struct trace_frame* trace = &t->trace;

	/* Restore the signal-hander frame data, if there was one. */
	set_child_data(t);
	/* If this signal had a user handler, and we just set up the
	 * callframe, and we need to restore the $sp for continued
	 * execution. */
	write_child_main_registers(tid, &trace->recorded_regs);
	/* Delivered the signal. */
	t->child_sig = 0;

	validate_args(trace->stop_reason, -1, t);
}

/**
 * Advance to the delivery of the deterministic signal |sig| and
 * update registers to what was recorded.  Return 0 if successful or 1
 * if an unhandled interrupt occurred.
 */
static int emulate_deterministic_signal(struct task* t,
					int sig, int stepi)
{
	pid_t tid = t->tid;

	continue_or_step(t, stepi);
	if (SIGCHLD == t->child_sig) {
		t->child_sig = 0;
		return emulate_deterministic_signal(t, sig, stepi);
	} else if (SIGTRAP == t->child_sig
		   && is_debugger_trap(t, sig, DETERMINISTIC, UNKNOWN, stepi)) {
		return 1;
	}
	assert_exec(t, t->child_sig == sig,
		    "Replay got unrecorded signal %d (expecting %d)",
		    t->child_sig, sig);

	if (SIG_SEGV_RDTSC == t->trace.stop_reason) {
		write_child_main_registers(tid, &t->trace.recorded_regs);
		/* We just "delivered" this pseudosignal. */
		t->child_sig = 0;
	} else {
		emulate_signal_delivery();
	}

	return 0;
}

/**
 * Run execution forwards for |t| until |t->trace.rbc| is reached,
 * and the $ip reaches the recorded $ip.  After that, deliver |sig| if
 * nonzero.  Return 0 if successful or 1 if an unhandled interrupt
 * occurred.
 */
static int emulate_async_signal(struct task* t,
				const struct user_regs_struct* regs, int sig,
				int stepi, int64_t* rcb)
{
	if (advance_to(t, regs, 0, stepi, rcb)) {
		return 1;
	}
	if (sig) {
		emulate_signal_delivery();
	}
	stop_hpc(t);
	return 0;
}

/**
 * Skip over the entry/exit of either an arm-desched-event or
 * disarm-desched-event ioctl(), as described by |ds|.  Return nonzero
 * if an unhandled interrupt occurred, zero if the ioctl() was
 * successfully skipped over.
 */
static int skip_desched_ioctl(struct task* t,
			      struct rep_desched_state* ds, int stepi)
{
	int ret, is_desched_syscall;

	/* Skip ahead to the syscall entry. */
	if (DESCHED_ENTER == ds->state
	    && (ret = cont_syscall_boundary(t, EMU, stepi))) {
		return ret;
	}
	ds->state = DESCHED_EXIT;

	read_child_registers(t->tid, &t->regs);
	is_desched_syscall = (DESCHED_ARM == ds->type ?
			      is_arm_desched_event_syscall(t, &t->regs) :
			      is_disarm_desched_event_syscall(t, &t->regs));
	assert_exec(t, is_desched_syscall,
		    "Failed to reach desched ioctl; at %s(%ld, %ld) instead (trace line %d)",
		    syscallname(t->regs.orig_eax), t->regs.ebx, t->regs.ecx,
		    get_trace_file_lines_counter());
	/* Emulate a return value of "0".  It's OK for us to hard-code
	 * that value here, because the syscallbuf lib aborts if a
	 * desched ioctl returns non-zero (it doesn't know how to
	 * handle that). */
	t->regs.eax = 0;
	write_child_registers(t->tid, &t->regs);
	step_exit_syscall_emu(t);
	return 0;
}

/**
 * Restore the recorded syscallbuf data to the tracee, preparing the
 * tracee for replaying the records.  Return the number of record
 * bytes and a pointer to the first record through outparams.
 */
static void prepare_syscallbuf_records(struct task* t,
				       size_t* num_rec_bytes,
				       const struct syscallbuf_record** first_rec)
{
	/* Save the current state of the header. */
	struct syscallbuf_hdr hdr = *t->syscallbuf_hdr;
	/* Read the recorded syscall buffer back into the shared
	 * region. */
	void* rec_addr;
	*num_rec_bytes = read_raw_data_direct(&t->trace,
					      t->syscallbuf_hdr,
					      SYSCALLBUF_BUFFER_SIZE,
					      &rec_addr);

	/* The stored num_rec_bytes in the header doesn't include the
	 * header bytes, but the stored trace data does. */
	*num_rec_bytes -= sizeof(sizeof(struct syscallbuf_hdr));
	assert(rec_addr == t->syscallbuf_child);
	assert(t->syscallbuf_hdr->num_rec_bytes == *num_rec_bytes);

	/* Restore the header state saved above, so that we start
	 * replaying with the header at the state it was when we
	 * reached this event during recording. */
	*t->syscallbuf_hdr = hdr;

	*first_rec = t->syscallbuf_hdr->recs;		
}

/**
 * Bail if |t| isn't at the buffered syscall |syscallno|.
 */
static void assert_at_buffered_syscall(struct task* t,
				       const struct user_regs_struct* regs,
				       int syscallno)
{
	void* ip = (void*)regs->eip;

	assert_exec(t, SYSCALLBUF_IS_IP_BUFFERED_SYSCALL(ip, t),
		    "(trace line %d) Bad ip %p: should have been buffered-syscall ip",
		    get_trace_file_lines_counter(), ip);
	assert_exec(t, regs->orig_eax == syscallno,
		    "(trace line %d) At %s; should have been at %s",
		    get_trace_file_lines_counter(),
		    syscallname(regs->orig_eax), syscallname(syscallno));
}

/**
 * Try to flush one buffered syscall as described by |flush|.  Return
 * nonzero if an unhandled interrupt occurred, and zero if the syscall
 * was flushed (in which case |flush->state == DONE|).
 */
static int flush_one_syscall(struct task* t,
			     struct rep_flush_state* flush, int stepi)
{
	pid_t tid = t->tid;
	const struct syscallbuf_record* rec = flush->rec;
	int ret;
	struct user_regs_struct regs;

	switch (flush->state) {
	case FLUSH_START:
		assert(0 == ((uintptr_t)rec & (sizeof(int) - 1)));

		debug("Replaying buffered `%s' which does%s use desched event",
		      syscallname(rec->syscallno),
		      !rec->desched ? " not" : "");

		if (!rec->desched) {
			flush->state = FLUSH_ENTER;
		} else {
			flush->state = FLUSH_ARM;
			flush->desched.type = DESCHED_ARM;
			flush->desched.state = DESCHED_ENTER;
		}
		return flush_one_syscall(t, flush, stepi);

	case FLUSH_ARM:
		/* Skip past the ioctl that armed the desched
		 * notification. */
		debug("  skipping over arm-desched ioctl");
		if ((ret = skip_desched_ioctl(t, &flush->desched, stepi))) {
			return ret;
		}
		flush->state = FLUSH_ENTER;
		return flush_one_syscall(t, flush, stepi);

	case FLUSH_ENTER:
		debug("  advancing to buffered syscall entry");
		if ((ret = cont_syscall_boundary(t, EMU, stepi))) {
			return ret;
		}
		read_child_registers(tid, &regs);
		assert_at_buffered_syscall(t, &regs, rec->syscallno);
		flush->state = FLUSH_EXIT;
		return flush_one_syscall(t, flush, stepi);

	case FLUSH_EXIT:
		debug("  advancing to buffered syscall exit");

		read_child_registers(tid, &regs);
		assert_at_buffered_syscall(t, &regs, rec->syscallno);

		regs.eax = rec->ret;
		write_child_registers(tid, &regs);
		step_exit_syscall_emu(t);

		/* XXX not pretty; should have this
		 * actually-replay-parts-of-trace logic centralized */
		if (SYS_write == rec->syscallno) {
			rep_maybe_replay_stdio_write(t);
		}

		if (!rec->desched) {
			flush->state = FLUSH_DONE;
			return 0;
		}
		flush->state = FLUSH_DISARM;
		flush->desched.type = DESCHED_DISARM;
		flush->desched.state = DESCHED_ENTER;
		return flush_one_syscall(t, flush, stepi);

	case FLUSH_DISARM:
		/* And skip past the ioctl that disarmed the desched
		 * notification. */
		debug("  skipping over disarm-desched ioctl");
		if ((ret = skip_desched_ioctl(t, &flush->desched, stepi))) {
			return ret;
		}
		flush->state = FLUSH_DONE;
		return 0;

	default:
		fatal("Unknown buffer-flush state %d", flush->state);
		return 0;	/* unreached */
	}
}

/**
 * Replay all the syscalls recorded in the interval between |t|'s
 * current execution point and the next non-syscallbuf event (the one
 * that flushed the buffer).  Return 0 if successful or 1 if an
 * unhandled interrupt occurred.
 */
static int flush_syscallbuf(struct task* t, struct rep_trace_step* step,
			    int stepi)
{
	struct rep_flush_state* flush = &step->flush;

	if (flush->need_buffer_restore) {
		prepare_syscallbuf_records(t,
					   &flush->num_rec_bytes_remaining,
					   &flush->rec);
		flush->need_buffer_restore = 0;

		debug("Prepared %d bytes of syscall records",
		      flush->num_rec_bytes_remaining);
	}

	while (flush->num_rec_bytes_remaining > 0) {
		int ret;
		size_t stored_rec_size;

		if ((ret = flush_one_syscall(t, flush, stepi))) {
			return ret;
		}

		assert(FLUSH_DONE == flush->state);

		stored_rec_size = stored_record_size(flush->rec->size);
		flush->rec = (const struct syscallbuf_record*)
			     ((byte*)flush->rec + stored_rec_size);
		flush->num_rec_bytes_remaining -= stored_rec_size;
		flush->state = FLUSH_START;

		debug("  %d bytes remain to flush",
		      flush->num_rec_bytes_remaining);
	}
	return 0;
}

/**
 * Try to execute |step|, adjusting for |req| if needed.  Return 0 if
 * |step| was made, or nonzero if there was a trap or |step| needs
 * more work.
 */
static int try_one_trace_step(struct task* t,
			      struct rep_trace_step* step,
			      const struct dbg_request* req)
{
	int stepi = (DREQ_STEP == req->type
		     && get_threadid(t) == req->target);
	switch (step->action) {
	case TSTEP_RETIRE:
		return 0;
	case TSTEP_ENTER_SYSCALL:
		return enter_syscall(t, step, stepi);
	case TSTEP_EXIT_SYSCALL:
		return exit_syscall(t, step, stepi);
	case TSTEP_DETERMINISTIC_SIGNAL:
		return emulate_deterministic_signal(t, step->signo, stepi);
	case TSTEP_PROGRAM_ASYNC_SIGNAL_INTERRUPT:
		return emulate_async_signal(t,
					    step->target.regs,
					    step->target.signo,
					    stepi,
					    &step->target.rcb);
	case TSTEP_FLUSH_SYSCALLBUF:
		return flush_syscallbuf(t, step, stepi);
	case TSTEP_DESCHED:
		return skip_desched_ioctl(t, &step->desched, stepi);
	default:
		fatal("Unhandled step type %d", step->action);
		return 0;
	}
}

static void replay_one_trace_frame(struct dbg_context* dbg,
				   struct task* t)
{
	struct dbg_request req;
	struct rep_trace_step step;
	int event = t->trace.stop_reason;
	int stop_sig = 0;

	debug("[line %d] %d: replaying %s; state %s",
	      get_trace_file_lines_counter(), t->rec_tid,
	      strevent(event), statename(t->trace.state));
	if (t->syscallbuf_hdr) {
		debug("    (syscllbufsz:%u, abrtcmt:%u)",
		      t->syscallbuf_hdr->num_rec_bytes,
		      t->syscallbuf_hdr->abort_commit);
	}

	/* Advance the trace until we've exec()'d the tracee before
	 * processing debugger requests.  Otherwise the debugger host
	 * will be confused about the initial executable image,
	 * rr's. */
	if (validate) {
		req = process_debugger_requests(dbg, t);
		assert(dbg_is_resume_request(&req));
	}

	if (t->child_sig != 0) {
		assert(event == -t->child_sig
		       || event == -(t->child_sig | DET_SIGNAL_BIT));
		t->child_sig = 0;
	}

	/* Ask the trace-interpretation code what to do next in order
	 * to retire the current frame. */
	memset(&step, 0, sizeof(step));

	switch (event) {
	case USR_INIT_SCRATCH_MEM: {
		/* for checksumming: make a note that this area is
		 * scratch and need not be validated. */
		struct mmapped_file file;
		read_next_mmapped_file_stats(&file);
		replay_init_scratch_memory(t, &file);
		add_scratch((void*)t->trace.recorded_regs.eax,
			    file.end - file.start);
		step.action = TSTEP_RETIRE;
		break;
	}
	case USR_UNSTABLE_EXIT:
		t->unstable = 1;
		/* fall through */
	case USR_EXIT:
		/* If the task was killed by a terminating signal,
		 * then it may have ended abruptly in a syscall or at
		 * some other random execution point.  That's bad for
		 * replay, because we detach from the task after we
		 * replay its "exit".  Since we emulate signal
		 * delivery, the task may happily carry on with
		 * (non-emulated!) execution after we detach.  That
		 * execution might include things like |rm -rf ~|.
		 *
		 * To ensure that the task really dies, we send it a
		 * terminating signal here.  One would like to use
		 * SIGKILL, but for not-understood reasons that causes
		 * shutdown hangs when joining the exited tracee.
		 * Other terminating signals have not been observed to
		 * hang, so that's what's used here.. */
		syscall(SYS_tkill, t->tid, SIGABRT);
		rep_sched_deregister_thread(&t);
		/* Early-return because |t| is gone now. */
		return;
	case USR_ARM_DESCHED:
	case USR_DISARM_DESCHED:
		step.action = TSTEP_DESCHED;
		step.desched.type = USR_ARM_DESCHED == event ?
				    DESCHED_ARM : DESCHED_DISARM;
		step.desched.state = DESCHED_ENTER;
		break;
	case USR_SYSCALLBUF_ABORT_COMMIT:
		t->syscallbuf_hdr->abort_commit = 1;
		step.action = TSTEP_RETIRE;
		break;
	case USR_SYSCALLBUF_FLUSH:
		step.action = TSTEP_FLUSH_SYSCALLBUF;
		step.flush.need_buffer_restore = 1;
		step.flush.num_rec_bytes_remaining = 0;
		break;
	case USR_SYSCALLBUF_RESET:
		t->syscallbuf_hdr->num_rec_bytes = 0;
		step.action = TSTEP_RETIRE;
		break;
	case USR_SCHED:
		step.action = TSTEP_PROGRAM_ASYNC_SIGNAL_INTERRUPT;
		step.target.rcb = t->trace.rbc;
		step.target.regs = &t->trace.recorded_regs;
		step.target.signo = 0;
		break;
	case SIG_SEGV_RDTSC:
		step.action = TSTEP_DETERMINISTIC_SIGNAL;
		step.signo = SIGSEGV;
		break;
	default:
		/* Pseudosignals are handled above. */
		assert(event > LAST_RR_PSEUDOSIGNAL);
		if (FIRST_DET_SIGNAL <= event && event <= LAST_DET_SIGNAL) {
			step.action = TSTEP_DETERMINISTIC_SIGNAL;
			step.signo = (-event & ~DET_SIGNAL_BIT);
			stop_sig = step.signo;
		} else if (event < 0) {
			assert(FIRST_ASYNC_SIGNAL <= event
			       && event <= LAST_ASYNC_SIGNAL);
			step.action = TSTEP_PROGRAM_ASYNC_SIGNAL_INTERRUPT;
			step.target.rcb = t->trace.rbc;
			step.target.regs = &t->trace.recorded_regs;
			step.target.signo = -event;
			stop_sig = step.target.signo;
		} else {
			assert(event > 0);
			/* XXX not so pretty ... */
			validate |= (t->trace.state == STATE_SYSCALL_EXIT
				     && event == SYS_execve);
			rep_process_syscall(t, &step);
		}
	}

	/* See the comment below about *not* resetting the hpc for
	 * buffer flushes.  Here, we're processing the *other* event,
	 * just after the buffer flush, where the rcb matters.  To
	 * simplify the advance-to-target code that follows (namely,
	 * making debugger interrupts simpler), pretend like the
	 * execution in the BUFFER_FLUSH didn't happen by resetting
	 * the rbc and compensating down the target rcb. */
	if (TSTEP_PROGRAM_ASYNC_SIGNAL_INTERRUPT == step.action) {
		uint64_t rcb_now = read_rbc(t->hpc);

		assert(step.target.rcb >= rcb_now);

		step.target.rcb -= rcb_now;
		reset_hpc(t, 0);
	}

	/* Advance until |step| has been fulfilled. */
	while (try_one_trace_step(t, &step, &req)) {
		struct user_regs_struct regs;

		/* Currently we only understand software breakpoints
		 * and successful stepi's. */
		assert(SIGTRAP == t->child_sig && "Unknown trap");

		read_child_registers(t->tid, &regs);
		if (TRAP_BKPT_USER == ip_breakpoint_type((void*)regs.eip)) {
			debug("  hit debugger breakpoint");
			/* SW breakpoint: $ip is just past the
			 * breakpoint instruction.  Move $ip back
			 * right before it. */
			regs.eip -= sizeof(int_3_insn);
			write_child_registers(t->tid, &regs);
		} else {
			debug("  finished debugger stepi");
			/* Successful stepi.  Nothing else to do. */
			assert(DREQ_STEP == req.type
			       && req.target == get_threadid(t));
		}
		/* Don't restart with SIGTRAP anywhere. */
		t->child_sig = 0;

		/* Notify the debugger and process any new requests
		 * that might have triggered before resuming. */
		dbg_notify_stop(dbg, get_threadid(t),	0x05/*gdb mandate*/);
		req = process_debugger_requests(dbg, t);
		assert(dbg_is_resume_request(&req));
	}

	if (dbg && stop_sig) {
		dbg_notify_stop(dbg, get_threadid(t), stop_sig);
	}

	/* We flush the syscallbuf in response to detecting *other*
	 * events, like signal delivery.  Flushing the syscallbuf is a
	 * sort of side-effect of reaching the other event.  But once
	 * we've flushed the syscallbuf during replay, we still must
	 * reach the execution point of the *other* event.  For async
	 * signals, that requires us to have an "intact" rbc, with the
	 * same value as it was when the last buffered syscall was
	 * retired during replay.  We'll be continuing from that rcb
	 * to reach the rcb we recorded at signal delivery.  So don't
	 * reset the counter for buffer flushes.  (It doesn't matter
	 * for non-async-signal types, which are deterministic.) */
	switch (t->trace.stop_reason) {
	case USR_SYSCALLBUF_ABORT_COMMIT:
	case USR_SYSCALLBUF_FLUSH:
	case USR_SYSCALLBUF_RESET:
		break;
	default:
		reset_hpc(t, 0);
	}
	debug_memory(t);
}

void replay(struct flags flags)
{
	struct dbg_context* dbg = NULL;

	if (!rr_flags()->autopilot) {
		unsigned short port = (rr_flags()->dbgport > 0) ?
				      rr_flags()->dbgport : getpid();
		/* Don't probe if the user specified a port.
		 * Explicitly selecting a port is usually done by
		 * scripts, which would presumably break if a
		 * different port were to be selected by rr (otherwise
		 * why would they specify a port in the first place).
		 * So fail with a clearer error message. */
		int probe = (rr_flags()->dbgport > 0) ?
			    DONT_PROBE : PROBE_PORT;
		dbg = dbg_await_client_connection("127.0.0.1", port, probe);
	}

	while (rep_sched_get_num_threads()) {
		replay_one_trace_frame(dbg, rep_sched_get_thread());
	}

	if (dbg) {
		/* TODO keep record of the code, if it's useful */
		dbg_notify_exit_code(dbg, 0);
	}

	log_info("Replayer successfully finished.");
	fflush(stdout);

	dbg_destroy_context(&dbg);
}

void emergency_debug(struct task* t)
{
	struct dbg_context* dbg;

	if (!isatty(STDERR_FILENO)) {
		errno = 0;
		fatal("(stderr not a tty, aborting emergency debugging)");
	}

	dbg = dbg_await_client_connection("127.0.0.1", t->tid, PROBE_PORT);
	process_debugger_requests(dbg, t);
	fatal("Can't resume execution from invalid state");
}

static int
breakpoint_cmp(void* pa, void* pb)
{
	struct breakpoint* a = (struct breakpoint*)pa;
	struct breakpoint* b = (struct breakpoint*)pb;
	return (intptr_t)a->addr - (intptr_t)b->addr;
}

RB_GENERATE_STATIC(breakpoint_tree, breakpoint, entry, breakpoint_cmp)
