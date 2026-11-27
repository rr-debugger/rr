/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_REMIX_H_
#define RR_REMIX_H_

#include <stdint.h>
#include <sys/types.h>
#include <sys/user.h>

/*
 * This file defines the interface between RemixModule in rr and the module
 * implementation in the tracee address space.
 */
typedef int64_t TraceFrameTime;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Registers of the emulated program. An implicit in/out parameter to
 * remix_execute, and can be used internally.
 */
extern struct user_regs_struct remix_registers;

/**
 * Emulated rcb counter. Making this 64-bit saves one byte in generated code
 * to increment the counter.
 */
extern uint64_t remix_rcb;

enum {
  MODULE_NEEDS_NOTIFY_WILL_WRITE_RANGE = 0x01,
};
/**
 * Flags exposed to rr RemixModule. Must be initialized during remix_init().
 */
extern uint64_t remix_module_flags;

/**
 * Registers to stop at, when STOP_AT_TARGET is passed to remix_execute.
 */
extern struct user_regs_struct remix_target_registers;

/**
 * RCB to stop at, when STOP_AT_TARGET is passed to remix_execute.
 */
extern uint64_t remix_target_rcb;

enum {
  REMIX_LOG_GEN = 0x1,
  REMIX_LOG_EXEC = 0x2,
  REMIX_LOG = 0x4,
  REMIX_LOG_TOOL = 0x8,
  REMIX_LOG_ALL = 0xffffffff
};
extern uint32_t remix_log_modules;

/**
 * When true, RemixModule should try to resolve SIGSEGV by extending the
 * stack.
 */
extern uint8_t remix_enable_stack_extension;

struct RemixAddressSpaceUid {
  /* Note that this is an address-space uid, and it's possible for different
   * thread groups to share the same address space. Hence processes with
   * different getpid()s can have the same values here.
   */
  pid_t rec_pid;
  uint32_t rec_pid_serial;
  uint32_t exec_count;
};

extern RemixAddressSpaceUid remix_uid;

struct RemixSighandlerState {
  uint64_t saved_pc;
  uint64_t fault_address;
  int32_t signal;
};

/**
 * RemixModule fills this in before triggering the sighandler.
 */
extern RemixSighandlerState remix_sighandler_state;

/**
 * Pointer to handler called when the remix module generates a crashing
 * signal, if non-null.
 */
extern void* remix_crash_handler;

enum RemixErrorCode {
  // No details were filled in.
  REMIX_ERROR_NONE = 0,
  // The instruction cannot be replayed, e.g. RDRAND.
  // `pc` is the PC of the instruction and `disassembly`
  // is its disassembly.
  REMIX_ERROR_INSTRUCTION_UNSUPPORTED_FOR_REPLAY,
  // The instruction is not supported on the current CPU.
  // `pc` is the PC of the instruction and `disassembly`
  // is its disassembly.
  REMIX_ERROR_INSTRUCTION_UNSUPPORTED_ON_THIS_CPU,
  // This instruction is not supported by remix.
  REMIX_ERROR_INSTRUCTION_UNSUPPORTED_FOR_REMIX,
  // 5-level page tables (57-bit addresses) are not supported.
  REMIX_ERROR_FIVE_LEVEL_PAGE_TABLES_UNSUPPORTED,
};

/**
 * When remix triggers a SIGABRT this structure may be filled in
 */
struct RemixErrorDetails {
  RemixErrorCode code;
  // Relevant application PC or 0 if none relevant
  uint64_t pc;
  // Disassembly of instruction at `pc` if relevant
  char disassembly[64];
  // Instruction class at `pc` if relevant (e.g., "sha")
  char instruction_family[16];
};

extern RemixErrorDetails remix_error_details;

// The total bounds of the range of memory reserved for remix.
// We must protect this against rogue buffered MADV_DONTNEEDs.
extern uintptr_t remix_range_start;
extern uintptr_t remix_range_end;

enum {
  // Generate STOPPED_SYNC_SIGNAL on CPUID executions.
  // If not set, trap to HANDLE_UNRECORDED_CPUID_FAULT_ADDRESS instead.
  REMIX_INIT_CPUID_FAULTING = 0x01,
  // Correct Intel RCP/RSQRT results to match AMD behavior, or vice versa
  REMIX_INIT_CORRECT_RCP_RSQRT = 0x02,
  // Correct LZCNT results if the trace was recorded on a CPU without LZCNT,
  // or vice versa.
  REMIX_INIT_CORRECT_LZCNT = 0x04,
  // Correct TZCNT results if the trace was recorded on a CPU without TZCNT,
  // or vice versa.
  REMIX_INIT_CORRECT_TZCNT = 0x08,
  // Correct XSAVE region layout between the host and the trace.
  // NB: Only handles different offsets.
  REMIX_INIT_CORRECT_XSAVE_REGION_LAYOUT = 0x10,
};

/**
 * Called when the remix module is loaded. |free_start| and |free_end| give
 * the memory range (page-aligned) of the address space usable by the module.
 *
 * |init_cookie| is passed in as -1 for the first |remix_init| in a session
 * and the result of each |remix_init| is passed to the next |remix_init|.
 */
intptr_t remix_init(RemixAddressSpaceUid* uid, void* free_start, void* free_end,
                    intptr_t init_cookie, uint32_t flags,
                    uint64_t tracee_xcr0);
/**
 * Called when the module is about to be unloaded.
 * It must fix up any state that is needed for normal execution to work
 * (e.g. un-write-protecting any pages that we write-protected for WX).
 */
void remix_will_unload();

/**
 * Called in a child after it has forked from the parent.
 */
void remix_did_fork_child(RemixAddressSpaceUid* uid, TraceFrameTime event);

/**
 * Called just before we exec. All threads will be torn down.
 */
void remix_will_exec(TraceFrameTime event);

enum {
  // Set when the last thread for this address space is exiting
  REMIX_EXIT_LAST_THREAD = 0x01,
  // Set when the last process for the entire session is exiting
  REMIX_EXIT_LAST_PROCESS = 0x02,
  // Set when remix exits because we've reached the specified end
  // of this remix run
  REMIX_EXIT_SYNTHETIC = 0x04,
};
/**
 * Called when a thread associated with this address space is exiting.
 */
void remix_will_exit(pid_t rec_tid, uint32_t rec_tid_serial,
                     TraceFrameTime event, uint32_t flags);
/**
 * Called when a thread associated with this address space is exiting and we're
 * about to unmap its scratch/syscallbuf.
 */
void remix_will_unmap(pid_t rec_tid, uint32_t rec_tid_serial,
                      TraceFrameTime event);

enum MemChangeType {
  MEM_MAP,
  MEM_PROTECT,
  MEM_WRITE,
  MEM_WRITE_BREAKPOINT,
  MEM_UNMAP,
};

struct ModifiedRangeAndProt {
  uint64_t start;
  uint64_t end;
  // In the remix module: if nonzero, then the location where we have saved the before-write data
  // In rr: if nonzero, then HAS_DATA_OFFSET + the location in the saved_before_write_data
  // vector where the saved data is.
  uint64_t saved_before_write_data;
  TraceFrameTime event;
  // -1 means no prot change. If >= 0, all pages intersecting [start, end)
  // have their protection changed.
  int prot;
  MemChangeType change_type;
};
enum {
  /** Stop at the next invocation of a syscall instruction.
   * We stop at the instruction, before executing it. (Entering the syscall
   * would make it impossible to return to the caller normally.)
   * Prefer using this over STOP_AT_TARGET/STOP_AT_IP when possible, since
   * it never has to invalidate fragments, whereas the others do.
   */
  STOP_AT_SYSCALL = 1,
  /** Stop when remix_target_registers and remix_target_rcb are reached */
  STOP_AT_TARGET = 2,
  /** Stops as soon as remix_target_registers.rip is reached. Always executes
   * at least one instruction, even if we're currently at the desired IP. */
  STOP_AT_IP = 3,
  /** Stops immediately after remix_target_registers.rip is executed. Always
   * executes at least one instruction. */
  STOP_AT_IP_EMULATE = 4,
  /** Stops as soon as remix_target_registers.rip is reached with an invalid
   * RSI. Always executes at least one instruction, even if we're currently
   * at the desired IP. */
  STOP_AT_BREAKPOINT_FAULT = 5,
  STOP_AT_MASK = 0xf,

  STOP_SINGLESTEP_NONE = 0,
  /** Combines with a STOP_AT. Stop after singlestepping. */
  STOP_SINGLESTEP = 0x10,
  /** Combines with a STOP_AT. Stop after singlestepping, treating
   * multiple iterations of a string instruction as one step. */
  STOP_SINGLESTEP_FAST_FORWARD = 0x20,
  STOP_SINGLESTEP_MASK = 0xf0,

  STOP_MATCH_IGNORE_GP_REGS = 0x100,
};
enum StopReason {
  /** Undefined value. Never returned by remix_execute. */
  STOPPED_NULL,
  /**
   * We met the condition requested.
   */
  STOPPED_NORMALLY = 1,
  /**
   * We hit a breakpoint instruction before meeting the condition.
   * The IP was advanced past the breakpoint instruction just like normal
   * execution would.
   */
  STOPPED_BREAKPOINT = 2,
  /**
   * We completed a singlestep. For STOP_AT_TARGET/STOP_AT_IP/STOP_AT_BREAKPOINT_FAULT
   * we may now be at the target.
   */
  STOPPED_SINGLESTEP = 3,
  /**
   * We stopped due to executing an instruction that should trigger a
   * synchronous signal under rr (e.g. RDTSC, INT). The instruction itself was
   * treated as a nop except for advancing the program counter. If
   * singlestepping was requested then we also completed the singlestep.
   * For STOP_AT_TARGET/STOP_AT_IP/STOP_AT_BREAKPOINT_FAULT we may now be at
   * the target.
   */
  STOPPED_SYNC_SIGNAL = 4
};

enum {
  /**
   * If CPUID faulting is enabled in the recording we'll stop at the instruction
   * and never execute it. Otherwise RemixModule needs to call
   * handle_unrecorded_cpuid_fault to handle it based on the CPUID
   * data stored in the recording header.
   * Set RIP to this to indicate that RemixModule should do that and then set
   * RIP to R8.
   */
  HANDLE_UNRECORDED_CPUID_FAULT_ADDRESS = 10
};

/**
 * Run application code until we reach a stopping condition.
 * We always stop at breakpoints (int 3, 0xcc) regardless of which
 * STOP_ condition is selected.
 * We can't handle watchpoints firing! That would require the ability to
 * interrupt a fragment anywhere, which is overhead we don't need for real
 * remix applications (so far).
 * Returns a STOPPED_ value.
 */
StopReason remix_execute(uint32_t flags, ModifiedRangeAndProt* ranges,
                         int num_ranges, pid_t rec_tid, uint32_t rec_tid_serial,
                         TraceFrameTime event);
/**
 * Called before a syscall-exit event or a signal-handler-transition event
 * changes the register state without executing code.
 * Tools must override this directly if needed, it's not dispatched through
 * ToolHooks.
 */
void remix_will_change_state(pid_t rec_tid, uint32_t rec_tid_serial,
                             TraceFrameTime event);

void remix_notify_modified_ranges(ModifiedRangeAndProt* ranges, int num_ranges);

enum RemixQuirk {
  // Note trace XSAVE component data for leaf arg2 with size/offset/flags in arg3/4/5.
  XSAVE_COMPONENT_DATA,
  // Allow RDRAND in the specified range arg2..arg3
  ALLOW_RDRAND,
};

void remix_apply_quirk(RemixQuirk quirk, void* arg2, void* arg3, void* arg4, void* arg5);

enum SyscallTraced { TRACED, UNTRACED };
enum SyscallPrivileged { PRIVILEGED, UNPRIVILEGED };
enum SyscallEnabled { RECORDING_ONLY, REPLAY_ONLY, RECORDING_AND_REPLAY, REPLAY_ASSIST };

struct RRPageSyscall {
  uint64_t addr;
  SyscallTraced traced;
  SyscallPrivileged privileged;
  SyscallEnabled enabled;
};
enum { REMIX_MAX_RR_PAGE_SYSCALLS = 16 };
extern RRPageSyscall remix_rr_page_syscalls[REMIX_MAX_RR_PAGE_SYSCALLS];

#ifdef __cplusplus
}

inline bool operator==(const RemixAddressSpaceUid& self,
                       const RemixAddressSpaceUid& other) {
  return self.rec_pid == other.rec_pid &&
         self.rec_pid_serial == other.rec_pid_serial &&
         self.exec_count == other.exec_count;
}
inline bool operator!=(const RemixAddressSpaceUid& self,
                       const RemixAddressSpaceUid& other) {
  return !(self == other);
}
#endif

#endif /* RR_REMIX_H_ */
