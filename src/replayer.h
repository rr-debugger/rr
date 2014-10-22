/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_REPLAYER_H_
#define RR_REPLAYER_H_

#include "Ticks.h"
#include "util.h"

struct dbg_context;
struct dbg_request;
class ReplaySession;

/**
 * Replay the trace.  argc, argv, and envp are this process's
 * parameters.
 * Returns an exit code: 0 on success.
 */
int replay(int argc, char* argv[], char** envp);

/**
 * Process the single debugger request |req|, made by |dbg| targeting
 * |t|, inside the session |session|.
 *
 * Callers should implement any special semantics they want for
 * particular debugger requests before calling this helper, to do
 * generic processing.
 */
void dispatch_debugger_request(ReplaySession& session, struct dbg_context* dbg,
                               Task* t, const struct dbg_request& req);

/**
 * Return true if |sig| is a signal that may be generated during
 * replay but should be ignored.  For example, SIGCHLD can be
 * delivered at almost point during replay when tasks exit, but it's
 * not part of the recording and shouldn't be delivered.
 *
 * TODO: can we do some clever sigprocmask'ing to avoid pending
 * signals altogether?
 */
bool is_ignored_replay_signal(int sig);

bool trace_instructions_up_to_event(uint64_t event);

/**
 * Start a debugging connection for |t| and return when there are no
 * more requests to process (usually because the debugger detaches).
 *
 * Unlike |emergency_debug()|, this helper doesn't attempt to
 * determine whether blocking rr on a debugger connection might be a
 * bad idea.  It will always open the debug socket and block awaiting
 * a connection.
 */
void start_debug_server(Task* t);

/**
 * The state of a (dis)arm-desched-event ioctl that's being processed.
 */
enum RepDeschedType {
  DESCHED_ARM,
  DESCHED_DISARM
};
enum RepDeschedState {
  DESCHED_ENTER,
  DESCHED_EXIT
};
struct rep_desched_state {
  /* Is this an arm or disarm request? */
  RepDeschedType type;
  /* What's our next step to retire the ioctl? */
  RepDeschedState state;
};

/**
 * The state of a syscallbuf flush that's being processed.  Syscallbuf
 * flushes are an odd duck among the trace-step types (along with the
 * desched step above), because they must maintain extra state in
 * order to know which commands to issue when being resumed after an
 * interruption.  So the process of flushing the syscallbuf will
 * mutate this state in between attempts to retire the step.
 */
enum RepFlushState {
  FLUSH_START,
  FLUSH_ARM,
  FLUSH_ENTER,
  FLUSH_EXIT,
  FLUSH_DISARM,
  FLUSH_DONE
};
/**
 * rep_flush_state is saved in Session and cloned with its Session, so it needs
 * to be simple data, i.e. not holding pointers to per-Session data.
 */
struct rep_flush_state {
  /* Nonzero when we need to write the syscallbuf data back to
   * the child. */
  int need_buffer_restore;
  /* After the data is restored, the number of record bytes that
   * still need to be flushed. */
  size_t num_rec_bytes_remaining;
  /* The offset of the next syscall record in both the rr and child
   * buffers */
  size_t syscall_record_offset;
  /* The next step to take. */
  RepFlushState state;
  /* Track the state of retiring desched arm/disarm ioctls, when
   * necessary. */
  struct rep_desched_state desched;
};

/**
 * Describes the next step to be taken in order to replay a trace
 * frame.
 */
enum RepTraceStepType {
  TSTEP_NONE,

  /* Frame has been replayed, done. */
  TSTEP_RETIRE,

  /* Enter/exit a syscall.  |syscall| describe what should be
   * done at entry/exit. */
  TSTEP_ENTER_SYSCALL,
  TSTEP_EXIT_SYSCALL,

  /* Advance to the deterministic signal |signo|. */
  TSTEP_DETERMINISTIC_SIGNAL,

  /* Advance until |target.ticks| have been retired and then
   * |target.ip| is reached. */
  TSTEP_PROGRAM_ASYNC_SIGNAL_INTERRUPT,

  /* Deliver signal |signo|. */
  TSTEP_DELIVER_SIGNAL,

  /* Replay the upcoming buffered syscalls.  |flush| tracks the
   * replay state.*/
  TSTEP_FLUSH_SYSCALLBUF,

  /* Emulate arming or disarming the desched event.  |desched|
   * tracks the replay state. */
  TSTEP_DESCHED,
};

enum ExecOrEmulate {
  EXEC = 0,
  EMULATE = 1
};

enum ExecOrEmulateReturn {
  EXEC_RETURN = 0,
  EMULATE_RETURN = 1
};

/**
 * rep_trace_step is saved in Session and cloned with its Session, so it needs
 * to be simple data, i.e. not holding pointers to per-Session data.
 */
struct rep_trace_step {
  RepTraceStepType action;

  union {
    struct {
      /* The syscall number we expect to
       * enter/exit. */
      int number;
      /* Is the kernel entry and exit for this
       * syscall emulated, that is, not executed? */
      ExecOrEmulate emu;
      /* The number of outparam arguments that are
       * set from what was recorded.
       * Only used when action is TSTEP_EXIT_SYSCALL. */
      ssize_t num_emu_args;
      /* Nonzero if the return from the syscall
       * should be emulated.  |emu| implies this. */
      ExecOrEmulateReturn emu_ret;
    } syscall;

    int signo;

    struct {
      Ticks ticks;
      int signo;
    } target;

    struct rep_flush_state flush;

    struct rep_desched_state desched;
  };
};

#endif /* RR_REPLAYER_H_ */
