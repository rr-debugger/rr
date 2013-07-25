/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

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

static const struct flags* rr_flags;

/* Nonzero after the first exec() has been observed during replay.
 * After this point, the first recorded binary image has been exec()d
 * over the initial rr image. */
static bool validate = FALSE;

RB_PROTOTYPE_STATIC(breakpoint_tree, breakpoint, entry, breakpoint_cmp)

static void debug_memory(struct context* ctx)
{
	/* dump memory as user requested */
	if (rr_flags->dump_on == ctx->trace.stop_reason
	    || rr_flags->dump_on == DUMP_ON_ALL
	    || rr_flags->dump_at == ctx->trace.global_time) {
		char pid_str[PATH_MAX];
		snprintf(pid_str, sizeof(pid_str) - 1, "%s/%d_%d_rep",
			 get_trace_path(),
			 ctx->child_tid, ctx->trace.global_time);
		print_process_memory(ctx, pid_str);
	}

	/* check memory checksum */
	if (validate
	    && ((rr_flags->checksum == CHECKSUM_ALL)
		|| (rr_flags->checksum == CHECKSUM_SYSCALL
		    && ctx->trace.state == STATE_SYSCALL_EXIT)
		|| (rr_flags->checksum <= ctx->trace.global_time))) {
		validate_process_memory(ctx);
	}
}

static void replay_init_scratch_memory(struct context* ctx,
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
    read_child_registers(ctx->child_tid, &orig_regs);

    struct user_regs_struct mmap_call = orig_regs;

    mmap_call.eax = SYS_mmap2;
    mmap_call.ebx = (uintptr_t)file->start;
    mmap_call.ecx = file->end - file->start;
    mmap_call.edx = PROT_NONE;
    mmap_call.esi = MAP_PRIVATE | MAP_ANONYMOUS;
    mmap_call.edi = -1;
    mmap_call.ebp = 0;

    inject_and_execute_syscall(ctx,&mmap_call);

    write_child_registers(ctx->child_tid,&orig_regs);
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

static dbg_threadid_t get_threadid(struct context* ctx)
{
	dbg_threadid_t thread = ctx->rec_tid;
	return thread;
}

static byte* read_mem(struct context* ctx, void* addr, size_t len,
		      size_t* read_len)
{
	ssize_t nread;
	void* buf = read_child_data_checked(ctx, len, addr, &nread);
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

static void set_sw_breakpoint(struct context* ctx, void* ip, trap_t type)
{
	struct breakpoint* bp = find_breakpoint(ip);
	if (!bp) {
		byte* orig_data_ptr;

		bp = sys_malloc_zero(sizeof(*bp));
		bp->addr = ip;

		orig_data_ptr = read_child_data(ctx, sizeof(int_3_insn),
						bp->addr);
		memcpy(&bp->overwritten_data, orig_data_ptr,
		       sizeof(int_3_insn));
		sys_free((void**)&orig_data_ptr);

		write_child_data_n(ctx->child_tid,
				   sizeof(int_3_insn), bp->addr, &int_3_insn);
		add_breakpoint(bp);
	}
	ref_breakpoint(bp, type);
}

static void remove_sw_breakpoint(struct context* ctx, void* ip, trap_t type)
{
	struct breakpoint* bp = find_breakpoint(ip);
	if (bp && 0 == unref_breakpoint(bp, type)) {
		write_child_data_n(ctx->child_tid,
				   sizeof(bp->overwritten_data), bp->addr,
				   &bp->overwritten_data);
		erase_breakpoint(bp);
		sys_free((void**)&bp);
	}
}

static void remove_internal_sw_breakpoint(struct context* ctx, void* ip)
{
	remove_sw_breakpoint(ctx, ip, TRAP_BKPT_INTERNAL);
}

static void remove_user_sw_breakpoint(struct context* ctx,
				      const struct dbg_request* req)
{
	assert(sizeof(int_3_insn) == req->mem.len);
	remove_sw_breakpoint(ctx, req->mem.addr, TRAP_BKPT_USER);
}

static void set_internal_sw_breakpoint(struct context* ctx, void* ip)
{
	set_sw_breakpoint(ctx, ip, TRAP_BKPT_INTERNAL);
}

static void set_user_sw_breakpoint(struct context* ctx,
				   const struct dbg_request* req)
{
	assert(sizeof(int_3_insn) == req->mem.len);
	set_sw_breakpoint(ctx, req->mem.addr, TRAP_BKPT_USER);
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
						    struct context* ctx)
{
	if (!dbg) {
		return continue_all_tasks;
	}
	while (1) {
		struct dbg_request req = dbg_get_request(dbg);
		struct context* target = NULL;

		if (dbg_is_resume_request(&req)) {
			return req;
		}

		target = (req.target > 0) ?
			 rep_sched_lookup_thread(req.target) : ctx;

		switch (req.type) {
		case DREQ_GET_CURRENT_THREAD: {
			dbg_reply_get_current_thread(dbg, get_threadid(ctx));
			continue;
		}
		case DREQ_GET_IS_THREAD_ALIVE:
			dbg_reply_get_is_thread_alive(dbg, !!target);
			continue;
		case DREQ_GET_MEM: {
			size_t len;
			byte* mem = read_mem(target, req.mem.addr, req.mem.len,
					     &len);
			dbg_reply_get_mem(dbg, mem, len);
			sys_free((void**)&mem);
			continue;
		}
		case DREQ_GET_OFFSETS:
			/* TODO */
			dbg_reply_get_offsets(dbg);
			continue;
		case DREQ_GET_REG: {
			struct user_regs_struct regs;
			dbg_regvalue_t val;

			read_child_registers(target->child_tid, &regs);
			val.value = get_reg(&regs, req.reg, &val.defined);
			dbg_reply_get_reg(dbg, val);
			continue;
		}
		case DREQ_GET_REGS: {
			struct user_regs_struct regs;
			struct dbg_regfile file;
			int i;
			dbg_regvalue_t* val;

			read_child_registers(target->child_tid, &regs);
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
			dbg_notify_stop(dbg, get_threadid(ctx), 0);
			continue;
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
static void validate_args(int event, int state, struct context* ctx)
{
	/* don't validate anything before execve is done as the actual
	 * process did not start prior to this point */
	if (!validate) {
		return;
	}
	assert_child_regs_are(ctx, &ctx->trace.recorded_regs, event, state);
}

/**
 * Continue until reaching either the "entry" of an emulated syscall,
 * or the entry or exit of an executed syscall.  |emu| is nonzero when
 * we're emulating the syscall.  Return 0 when the next syscall
 * boundary is reached, or nonzero if advancing to the boundary was
 * interrupted by an unknown trap.
 */
enum { EXEC = 0, EMU = 1 };
static int cont_syscall_boundary(struct context* ctx, int emu, int stepi)
{
	pid_t tid = ctx->child_tid;

	if (emu && stepi) {
		sys_ptrace_sysemu_singlestep(tid);
	} else if (emu) {
		sys_ptrace_sysemu(tid);
	} else if (stepi) {
		sys_ptrace_singlestep(tid);
	} else {
		sys_ptrace_syscall(tid);
	}
	sys_waitpid(tid, &ctx->status);

	switch ((ctx->child_sig = signal_pending(ctx->status))) {
	case 0:
		break;
	case SIGCHLD:
		/* SIGCHLD is pending, do not deliver it, wait for it
		 * to appear in the trace SIGCHLD is the only signal
		 * that should ever be generated as all other signals
		 * are emulated! */
		return cont_syscall_boundary(ctx, emu, stepi);
	case SIGTRAP:
		return 1;
	default:
		log_err("Replay got unrecorded signal %d", ctx->child_sig);
		emergency_debug(ctx);
	}

	assert(ctx->child_sig == 0);

	return 0;
}

/**
 *  Step over the system call instruction to "exit" the emulated
 *  syscall.
 *
 * XXX verify that this can't be interrupted by a breakpoint trap
 */
static void step_exit_syscall_emu(struct context *ctx)
{
	pid_t tid = ctx->child_tid;
	struct user_regs_struct regs;

	read_child_registers(tid, &regs);

	sys_ptrace_sysemu_singlestep(tid);
	sys_waitpid(tid, &ctx->status);

	write_child_registers(tid, &regs);

	ctx->status = 0;
}

/**
 * Advance to the next syscall entry (or virtual entry) according to
 * |step|.  Return 0 if successful, or nonzero if an unhandled trap
 * occurred.
 */
static int enter_syscall(struct context* ctx,
			 const struct rep_trace_step* step,
			 int stepi)
{
	int ret;
	if ((ret = cont_syscall_boundary(ctx, step->syscall.emu, stepi))) {
		return ret;
	}
	validate_args(step->syscall.no, STATE_SYSCALL_ENTRY, ctx);
	return ret;
}

/**
 * Advance past the reti (or virtual reti) according to |step|.
 * Return 0 if successful, or nonzero if an unhandled trap occurred.
 */
static int exit_syscall(struct context* ctx,
			const struct rep_trace_step* step,
			int stepi)
{
	int i, emu = step->syscall.emu;

	if (!emu) {
		int ret = cont_syscall_boundary(ctx, emu, stepi);
		if (ret) {
			return ret;
		}
	}

	for (i = 0; i < step->syscall.num_emu_args; ++i) {
		set_child_data(ctx);
	}
	if (step->syscall.emu_ret) {
		set_return_value(ctx);
	}
	validate_args(step->syscall.no, STATE_SYSCALL_EXIT, ctx);

	if (emu) {
		step_exit_syscall_emu(ctx);
	}
	return 0;
}

/**
 * Advance |ctx| to the next signal or trap.  If |stepi| is |STEPI|,
 * then execution resumes by single-stepping.  Otherwise it continues
 * normally.  The delivered signal is recorded in |ctx->child_sig|.
 */
enum { DONT_STEPI = 0, STEPI };
static void continue_or_step(struct context* ctx, int stepi)
{
	pid_t tid = ctx->child_tid;

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
	sys_waitpid(tid, &ctx->status);

	ctx->child_sig = signal_pending(ctx->status);
	if (0 == ctx->child_sig) {
		struct user_regs_struct regs;
		read_child_registers(ctx->child_tid, &regs);

		log_err("Replaying `%s' (line %d): expecting tracee signal or trap, but instead at `%s' (rcb: %llu)",
			strevent(ctx->trace.stop_reason),
			get_trace_file_lines_counter(),
			strevent(regs.orig_eax), read_rbc(ctx->hpc));
		emergency_debug(ctx);
	}
}

/**
 * Return nonzero if |ctx| was stopped for a breakpoint trap (int3),
 * as opposed to a trace trap.  Return zero in the latter case.
 */
static int is_breakpoint_trap(struct context* ctx)
{
	siginfo_t si;

	assert(SIGTRAP == ctx->child_sig);

	sys_ptrace_getsiginfo(ctx->child_tid, &si);
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
static trap_t compute_trap_type(struct context* ctx, int target_sig,
				sigdelivery_t delivery, execstate_t exec_state,
				int stepi)
{
	struct user_regs_struct regs;
	void* ip;
	trap_t trap_type;

	assert(SIGTRAP == ctx->child_sig);

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

	read_child_registers(ctx->child_tid, &regs);
	ip = (void*)regs.eip;
	trap_type = ip_breakpoint_type(ip);
	if (TRAP_BKPT_USER == trap_type || TRAP_BKPT_INTERNAL == trap_type) {
		assert(is_breakpoint_trap(ctx));
		return trap_type;
	}

	if (is_breakpoint_trap(ctx)) {
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
 * Return nonzero if |ctx|'s trap is for the debugger, zero otherwise.
 */
static int is_debugger_trap(struct context* ctx, int target_sig,
			    sigdelivery_t delivery, execstate_t exec_state,
			    int stepi)
{
	trap_t type = compute_trap_type(ctx, target_sig, delivery, exec_state,
					stepi);
	assert(TRAP_BKPT_INTERNAL != type);
	return TRAP_NONE != type;
}

static void guard_overshoot(struct context* ctx,
			    uint64_t target, uint64_t current)
{
	if (current <= target) {
		return;
	}
	log_err("Replay diverged: overshot target rcb=%llu, reached=%llu\n"
		"    replaying trace line %d",
		target, current,
		get_trace_file_lines_counter());
	emergency_debug(ctx);
	/* not reached */
}

static void guard_unexpected_signal(struct context* ctx)
{
	int event;

	/* "0" normally means "syscall", but continue_or_step() guards
	 * against unexpected syscalls.  So the caller must have set
	 * "0" intentionally. */
	if (0 == ctx->child_sig || SIGTRAP == ctx->child_sig) {
		return;
	}
	if (ctx->child_sig) {
		event = -ctx->child_sig;
	} else {
		struct user_regs_struct regs;
		read_child_registers(ctx->child_tid, &regs);
		event = MAX(0, regs.orig_eax);
	}
	log_err("Replay got unrecorded event %s while awaiting signal\n"
		"    replaying trace line %d",
		strevent(event),
		get_trace_file_lines_counter());
	emergency_debug(ctx);
	/* not reached */
}

static int is_same_execution_point(uint64_t rec_rcb,
				   const struct user_regs_struct* rec_regs,
				   uint64_t rep_rcb,
				   const struct user_regs_struct* rep_regs)
{
	return (rep_rcb == rep_rcb
		&& 0 == compare_register_files("rep interrupt", rep_regs,
					       "rec", rec_regs, 0, 0));
}

/**
 * Run execution forwards for |ctx| until |ctx->trace.rbc| is reached,
 * and the $ip reaches the recorded $ip.  Return 0 if successful or 1
 * if an unhandled interrupt occurred.  |sig| is the pending signal to
 * be delivered; it's only used to distinguish debugger-related traps
 * from traps related to replaying execution.
 */
static int advance_to(struct context* ctx, uint64_t rcb,
		      const struct user_regs_struct* regs, int sig,
		      int stepi)
{
	pid_t tid = ctx->child_tid;
	void* ip = (void*)regs->eip;
	uint64_t rcb_now;

	assert(ctx->hpc->rbc.fd > 0);
	assert(ctx->child_sig == 0);

	/* Step 1: advance to the target rcb (minus a slack region) as
	 * quickly as possible by programming the hpc. */
	rcb_now = read_rbc(ctx->hpc);

	debug("Advancing to rcb:%llu/eip:%p from rcb:%llu",
	      rcb, (void*)regs->eip, rcb_now);

	/* XXX should we only do this if (rcb > 10000)? */
	while (rcb > SKID_SIZE && rcb_now < rcb - SKID_SIZE) {
		if (SIGTRAP == ctx->child_sig) {
			/* We proved we're not at the execution
			 * target, and we haven't set any internal
			 * breakpoints, and we're not temporarily
			 * internally single-stepping, so we must have
			 * hit a debugger breakpoint or the debugger
			 * was single-stepping the tracee.  (The
			 * debugging code will verify that.) */
			return 1;
		}
		ctx->child_sig = 0;

		reset_hpc(ctx, rcb - rcb_now - SKID_SIZE);

		continue_or_step(ctx, stepi);
		if (SIGIO == ctx->child_sig || SIGCHLD == ctx->child_sig) {
			/* Tracees can receive SIGCHLD at pretty much
			 * any time during replay.  If we recorded
			 * delivery, we'll manually replay it
			 * eventually (or already have).  Just ignore
			 * here. */
			ctx->child_sig = 0;
		}
		guard_unexpected_signal(ctx);

		/* TODO this assertion won't catch many spurious
		 * SIGIOs; should assert that the siginfo says the
		 * source is io-ready and the fd is the child's fd. */
		if (fcntl(ctx->hpc->rbc.fd, F_GETOWN) != tid) {
			fatal("Scheduled task %d doesn't own hpc; replay divergence", tid);
		}

		rcb_now = read_rbc(ctx->hpc);
	}
	guard_overshoot(ctx, rcb, rcb_now);

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
	while (rcb_now <= rcb) {
		/* Invariants here are
		 *  o rcb_now is up-to-date
		 *  o rcb_now <= rcb
		 *
		 * Possible state of the execution of |ctx|
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
		at_target = is_same_execution_point(rcb, regs,
						    rcb_now, &regs_now);
		if (SIGTRAP == ctx->child_sig) {
			trap_t trap_type = compute_trap_type(
				ctx, ASYNC, sig,
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

				ctx->child_sig = 0;
				regs_now.eip -= sizeof(int_3_insn);
				write_child_registers(tid, &regs_now);
				/* We maintain the
				 * "'rcb_now'-is-up-to-date" invariant
				 * above here even though we don't
				 * re-read the rbc, because executing
				 * the trap instruction couldn't have
				 * retired a branch. */
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
				ctx->child_sig = 0;
				break;
			}
		}
		/* We had to keep the internal breakpoint set (if it
		 * was when we entered the loop) for the checks above.
		 * But now we're either done (at the target) or about
		 * to resume execution in one of a variety of ways,
		 * and it's simpler to start out knowing that the
		 * breakpoint isn't set. */
		remove_internal_sw_breakpoint(ctx, ip);

		if (at_target) {
			/* Case (2) above: done. */
			return 0;
		}

		/* At this point, we've proven that we're not at the
		 * target execution point, and we've ensured the
		 * internal breakpoint is unset. */
		debug("  running from rcb:%llu to target rcb:%llu",
		      rcb_now, rcb);

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
			set_internal_sw_breakpoint(ctx, ip);
			continue_or_step(ctx, stepi);
		} else {
			/* Case (3) above: we can't put a breakpoint
			 * on the $ip, because resuming execution
			 * would just trap and we'd be back where we
			 * started.  Single-step past it. */
			debug("    (single-stepping over target $ip)");
			continue_or_step(ctx, STEPI);
		}

		if (SIGCHLD == ctx->child_sig) {
			/* See the long comment in "Step 1" above. */
			ctx->child_sig = 0;
		}
		guard_unexpected_signal(ctx);

		/* Maintain the "'rcb_now'-is-up-to-date"
		 * invariant. */
		rcb_now = read_rbc(ctx->hpc);
	}
	guard_overshoot(ctx, rcb, rcb_now);

	return 0;
}

static void emulate_signal_delivery()
{
	/* We are now at the exact point in the child where the signal
	 * was recorded, emulate it using the next trace line (records
	 * the state at sighandler entry). */
	struct context* ctx = rep_sched_get_thread();
	pid_t tid = ctx->child_tid;
	struct trace_frame* trace = &ctx->trace;

	/* Restore the signal-hander frame data, if there was one. */
	if (!set_child_data(ctx)) {
		/* No signal handler.  Advance execution to the point
		 * we recorded. */
		reset_hpc(ctx, 0);
		/* TODO what happens if we step on a breakpoint? */
		advance_to(ctx, ctx->trace.rbc, &trace->recorded_regs,
			   /*no signal*/0, DONT_STEPI);
		/* (|advance_to()| just asserted that the registers
		 * match what was recorded.) */
	} else {
		/* Signal handler; we just set up the callframe.
		 * Continuing execution will run that code. */
		write_child_main_registers(tid, &trace->recorded_regs);
	}
	/* Delivered the signal. */
	ctx->child_sig = 0;

	validate_args(ctx->trace.stop_reason, -1, ctx);
}

/**
 * Advance to the delivery of the deterministic signal |sig| and
 * update registers to what was recorded.  Return 0 if successful or 1
 * if an unhandled interrupt occurred.
 */
static int emulate_deterministic_signal(struct context* ctx,
					int sig, int stepi)
{
	pid_t tid = ctx->child_tid;

	continue_or_step(ctx, stepi);
	if (SIGCHLD == ctx->child_sig) {
		ctx->child_sig = 0;
		return emulate_deterministic_signal(ctx, sig, stepi);
	} else if (SIGTRAP == ctx->child_sig
		   && is_debugger_trap(ctx, sig, DETERMINISTIC, UNKNOWN, stepi)) {
		return 1;
	} else if (ctx->child_sig != sig) {
		log_err("Replay got unrecorded signal %d (expecting %d)",
			ctx->child_sig, sig);
		emergency_debug(ctx);
		return 1;		/* not reached */
	}

	if (SIG_SEGV_RDTSC == ctx->trace.stop_reason) {
		write_child_main_registers(tid, &ctx->trace.recorded_regs);
		/* We just "delivered" this pseudosignal. */
		ctx->child_sig = 0;
	} else {
		emulate_signal_delivery();
	}

	return 0;
}

/**
 * Run execution forwards for |ctx| until |ctx->trace.rbc| is reached,
 * and the $ip reaches the recorded $ip.  After that, deliver |sig| if
 * nonzero.  Return 0 if successful or 1 if an unhandled interrupt
 * occurred.
 */
static int emulate_async_signal(struct context* ctx, uint64_t rcb,
				const struct user_regs_struct* regs, int sig,
				int stepi)
{
	if (advance_to(ctx, rcb, regs, 0, stepi)) {
		return 1;
	}
	if (sig) {
		emulate_signal_delivery();
	}
	stop_hpc(ctx);
	return 0;
}

/**
 * Skip over the entry/exit of either an arm-desched-event or
 * disarm-desched-event ioctl(), as described by |ds|.  Return nonzero
 * if an unhandled interrupt occurred, zero if the ioctl() was
 * successfully skipped over.
 */
static int skip_desched_ioctl(struct context* ctx,
			      struct rep_desched_state* ds, int stepi)
{
	int ret, is_desched_syscall;
	struct user_regs_struct regs;

	/* Skip ahead to the syscall entry. */
	if (DESCHED_ENTER == ds->state
	    && (ret = cont_syscall_boundary(ctx, EMU, stepi))) {
		return ret;
	}
	ds->state = DESCHED_EXIT;

	read_child_registers(ctx->child_tid, &regs);
	is_desched_syscall = DESCHED_ARM == ds->type ?
			     is_arm_desched_event_syscall(ctx, &regs) :
			     is_disarm_desched_event_syscall(ctx, &regs);
	if (!is_desched_syscall) {
		log_err("Failed to reach desched ioctl; at %s(%ld, %ld) instead",
			syscallname(regs.orig_eax), regs.ebx, regs.ecx);
		emergency_debug(ctx);
	}

	/* Emulate a return value of "0".  It's OK for us to hard-code
	 * that value here, because the syscallbuf lib aborts if a
	 * desched ioctl returns non-zero (it doesn't know how to
	 * handle that). */
	regs.eax = 0;
	write_child_registers(ctx->child_tid, &regs);
	step_exit_syscall_emu(ctx);
	return 0;
}

/**
 * Restore the recorded syscallbuf data to the tracee, preparing the
 * tracee for replaying the records.  Return the number of record
 * bytes and a pointer to the first record through outparams.
 */
static void prepare_syscallbuf_records(struct context* ctx,
				       size_t* num_rec_bytes,
				       const struct syscallbuf_record** first_rec)
{
	/* Save the current state of the header. */
	struct syscallbuf_hdr hdr = *ctx->syscallbuf_hdr;
	/* Read the recorded syscall buffer back into the shared
	 * region. */
	void* rec_addr;
	*num_rec_bytes = read_raw_data_direct(&ctx->trace,
					      ctx->syscallbuf_hdr,
					      SYSCALLBUF_BUFFER_SIZE,
					      &rec_addr);

	/* The stored num_rec_bytes in the header doesn't include the
	 * header bytes, but the stored trace data does. */
	*num_rec_bytes -= sizeof(sizeof(struct syscallbuf_hdr));
	assert(rec_addr == ctx->syscallbuf_child);
	assert(ctx->syscallbuf_hdr->num_rec_bytes == *num_rec_bytes);

	/* Restore the header state saved above, so that we start
	 * replaying with the header at the state it was when we
	 * reached this event during recording. */
	*ctx->syscallbuf_hdr = hdr;

	*first_rec = ctx->syscallbuf_hdr->recs;		
}

/**
 * Bail if |ctx| isn't at the buffered syscall |syscallno|.
 */
static void assert_at_buffered_syscall(struct context* ctx,
				       const struct user_regs_struct* regs,
				       int syscallno)
{
	void* ip = (void*)regs->eip;
	if (!SYSCALLBUF_IS_IP_BUFFERED_SYSCALL(ip, ctx)) {
		log_err("Bad ip %p: should have been buffered-syscall ip", ip);
		emergency_debug(ctx);
	}
	if (regs->orig_eax != syscallno) {
		log_err("At %s; should have been at %s",
			syscallname(regs->orig_eax), syscallname(syscallno));
		emergency_debug(ctx);
	}
}

/**
 * Try to flush one buffered syscall as described by |flush|.  Return
 * nonzero if an unhandled interrupt occurred, and zero if the syscall
 * was flushed (in which case |flush->state == DONE|).
 */
static int flush_one_syscall(struct context* ctx,
			     struct rep_flush_state* flush, int stepi)
{
	pid_t tid = ctx->child_tid;
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
		return flush_one_syscall(ctx, flush, stepi);

	case FLUSH_ARM:
		/* Skip past the ioctl that armed the desched
		 * notification. */
		debug("  skipping over arm-desched ioctl");
		if ((ret = skip_desched_ioctl(ctx, &flush->desched, stepi))) {
			return ret;
		}
		flush->state = FLUSH_ENTER;
		return flush_one_syscall(ctx, flush, stepi);

	case FLUSH_ENTER:
		debug("  advancing to buffered syscall entry");
		if ((ret = cont_syscall_boundary(ctx, EMU, stepi))) {
			return ret;
		}
		read_child_registers(tid, &regs);
		assert_at_buffered_syscall(ctx, &regs, rec->syscallno);
		flush->state = FLUSH_EXIT;
		return flush_one_syscall(ctx, flush, stepi);

	case FLUSH_EXIT:
		debug("  advancing to buffered syscall exit");

		read_child_registers(tid, &regs);
		assert_at_buffered_syscall(ctx, &regs, rec->syscallno);

		regs.eax = rec->ret;
		write_child_registers(tid, &regs);
		step_exit_syscall_emu(ctx);

		/* XXX not pretty; should have this
		 * actually-replay-parts-of-trace logic centralized */
		if (SYS_write == rec->syscallno) {
			rep_maybe_replay_stdio_write(ctx, rr_flags->redirect);
		}

		if (!rec->desched) {
			flush->state = FLUSH_DONE;
			return 0;
		}
		flush->state = FLUSH_DISARM;
		flush->desched.type = DESCHED_DISARM;
		flush->desched.state = DESCHED_ENTER;
		return flush_one_syscall(ctx, flush, stepi);

	case FLUSH_DISARM:
		/* And skip past the ioctl that disarmed the desched
		 * notification. */
		debug("  skipping over disarm-desched ioctl");
		if ((ret = skip_desched_ioctl(ctx, &flush->desched, stepi))) {
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
 * Replay all the syscalls recorded in the interval between |ctx|'s
 * current execution point and the next non-syscallbuf event (the one
 * that flushed the buffer).  Return 0 if successful or 1 if an
 * unhandled interrupt occurred.
 */
static int flush_syscallbuf(struct context* ctx, struct rep_trace_step* step,
			    int stepi)
{
	struct rep_flush_state* flush = &step->flush;

	if (flush->need_buffer_restore) {
		prepare_syscallbuf_records(ctx,
					   &flush->num_rec_bytes_remaining,
					   &flush->rec);
		flush->need_buffer_restore = 0;

		debug("Prepared %d bytes of syscall records",
		      flush->num_rec_bytes_remaining);
	}

	while (flush->num_rec_bytes_remaining > 0) {
		int ret;
		size_t stored_rec_size;

		if ((ret = flush_one_syscall(ctx, flush, stepi))) {
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
static int try_one_trace_step(struct context* ctx,
			      struct rep_trace_step* step,
			      const struct dbg_request* req)
{
	int stepi = (DREQ_STEP == req->type
		     && get_threadid(ctx) == req->target);
	switch (step->action) {
	case TSTEP_RETIRE:
		return 0;
	case TSTEP_ENTER_SYSCALL:
		return enter_syscall(ctx, step, stepi);
	case TSTEP_EXIT_SYSCALL:
		return exit_syscall(ctx, step, stepi);
	case TSTEP_DETERMINISTIC_SIGNAL:
		return emulate_deterministic_signal(ctx, step->signo, stepi);
	case TSTEP_PROGRAM_ASYNC_SIGNAL_INTERRUPT:
		return emulate_async_signal(ctx,
					    step->target.rcb,
					    step->target.regs,
					    step->target.signo,
					    stepi);
	case TSTEP_FLUSH_SYSCALLBUF:
		return flush_syscallbuf(ctx, step, stepi);
	case TSTEP_DESCHED:
		return skip_desched_ioctl(ctx, &step->desched, stepi);
	default:
		fatal("Unhandled step type %d", step->action);
		return 0;
	}
}

static void replay_one_trace_frame(struct dbg_context* dbg,
				   struct context* ctx)
{
	struct dbg_request req;
	struct rep_trace_step step;
	int event = ctx->trace.stop_reason;
	int stop_sig = 0;

	debug("%d: replaying event %s, state %s",
	      ctx->rec_tid,
	      strevent(event), statename(ctx->trace.state));
	if (ctx->syscallbuf_hdr) {
		debug("    (syscllbufsz:%u, abrtcmt:%u)",
		      ctx->syscallbuf_hdr->num_rec_bytes,
		      ctx->syscallbuf_hdr->abort_commit);
	}

	/* Advance the trace until we've exec()'d the tracee before
	 * processing debugger requests.  Otherwise the debugger host
	 * will be confused about the initial executable image,
	 * rr's. */
	if (validate) {
		req = process_debugger_requests(dbg, ctx);
		assert(dbg_is_resume_request(&req));
	}

	/* print some kind of progress */
	if (ctx->trace.global_time % 10000 == 0) {
		fprintf(stderr, "time: %u\n",ctx->trace.global_time);
	}

	if (ctx->child_sig != 0) {
		assert(event == -ctx->child_sig
		       || event == -(ctx->child_sig | DET_SIGNAL_BIT));
		ctx->child_sig = 0;
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
		replay_init_scratch_memory(ctx, &file);
		add_scratch((void*)ctx->trace.recorded_regs.eax,
			    file.end - file.start);
		step.action = TSTEP_RETIRE;
		break;
	}
	case USR_EXIT:
		rep_sched_deregister_thread(&ctx);
		/* Early-return because |ctx| is gone now. */
		return;
	case USR_ARM_DESCHED:
	case USR_DISARM_DESCHED:
		step.action = TSTEP_DESCHED;
		step.desched.type = USR_ARM_DESCHED == event ?
				    DESCHED_ARM : DESCHED_DISARM;
		step.desched.state = DESCHED_ENTER;
		break;
	case USR_SYSCALLBUF_ABORT_COMMIT:
		ctx->syscallbuf_hdr->abort_commit = 1;
		step.action = TSTEP_RETIRE;
		break;
	case USR_SYSCALLBUF_FLUSH:
		step.action = TSTEP_FLUSH_SYSCALLBUF;
		step.flush.need_buffer_restore = 1;
		step.flush.num_rec_bytes_remaining = 0;
		break;
	case USR_SYSCALLBUF_RESET:
		ctx->syscallbuf_hdr->num_rec_bytes = 0;
		step.action = TSTEP_RETIRE;
		break;
	case USR_SCHED:
		step.action = TSTEP_PROGRAM_ASYNC_SIGNAL_INTERRUPT;
		step.target.rcb = ctx->trace.rbc;
		step.target.regs = &ctx->trace.recorded_regs;
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
			step.target.rcb = ctx->trace.rbc;
			step.target.regs = &ctx->trace.recorded_regs;
			step.target.signo = -event;
			stop_sig = step.target.signo;
		} else {
			assert(event > 0);
			/* XXX not so pretty ... */
			validate |= (ctx->trace.state == STATE_SYSCALL_EXIT
				     && event == SYS_execve);
			rep_process_syscall(ctx, rr_flags->redirect, &step);
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
		uint64_t rcb_now = read_rbc(ctx->hpc);

		assert(step.target.rcb >= rcb_now);

		step.target.rcb -= rcb_now;
		reset_hpc(ctx, 0);
	}

	/* Advance until |step| has been fulfilled. */
	while (try_one_trace_step(ctx, &step, &req)) {
		struct user_regs_struct regs;

		/* Currently we only understand software breakpoints
		 * and successful stepi's. */
		assert(SIGTRAP == ctx->child_sig && "Unknown trap");

		read_child_registers(ctx->child_tid, &regs);
		if (TRAP_BKPT_USER == ip_breakpoint_type((void*)regs.eip)) {
			/* SW breakpoint: $ip is just past the
			 * breakpoint instruction.  Move $ip back
			 * right before it. */
			regs.eip -= sizeof(int_3_insn);
			write_child_registers(ctx->child_tid, &regs);
		} else {
			/* Successful stepi.  Nothing else to do. */
			assert(DREQ_STEP == req.type
			       && req.target == get_threadid(ctx));
		}
		/* Don't restart with SIGTRAP anywhere. */
		ctx->child_sig = 0;

		/* Notify the debugger and process any new requests
		 * that might have triggered before resuming. */
		dbg_notify_stop(dbg, get_threadid(ctx),	0x05/*gdb mandate*/);
		req = process_debugger_requests(dbg, ctx);
		assert(dbg_is_resume_request(&req));
	}

	if (dbg && stop_sig) {
		dbg_notify_stop(dbg, get_threadid(ctx), stop_sig);
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
	switch (ctx->trace.stop_reason) {
	case USR_SYSCALLBUF_ABORT_COMMIT:
	case USR_SYSCALLBUF_FLUSH:
	case USR_SYSCALLBUF_RESET:
		break;
	default:
		reset_hpc(ctx, 0);
	}
	debug_memory(ctx);
}

static void check_initial_register_file()
{
	rep_sched_get_thread();
}

void replay(struct flags flags)
{
	struct dbg_context* dbg = NULL;

	rr_flags = &flags;

	if (!rr_flags->autopilot) {
		dbg = dbg_await_client_connection("127.0.0.1",
						  rr_flags->dbgport);
	}

	check_initial_register_file();

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

void emergency_debug(struct context* ctx)
{
	struct dbg_context* dbg;

	if (!isatty(STDERR_FILENO)) {
		errno = 0;
		fatal("(stderr not a tty, aborting emergency debugging)");
	}

	dbg = dbg_await_client_connection("127.0.0.1", ctx->child_tid);
	process_debugger_requests(dbg, ctx);
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
