/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_DBG_GDB_H_
#define RR_DBG_GDB_H_

#include <stddef.h>
#include <sys/types.h>

#include <ostream>
#include <vector>

#include "Flags.h"
#include "registers.h"
#include "session.h"

#define DBG_SOCKET_READY_SIG SIGURG

struct dbg_context;

/**
 * Descriptor for task within a task group.  Note: on linux, we can
 * uniquely identify any thread by its |tid| (ignoring pid
 * namespaces).
 */
struct dbg_threadid_t {
  pid_t pid;
  pid_t tid;

  bool operator==(const dbg_threadid_t& o) const {
    return pid == o.pid && tid == o.tid;
  }
};

inline static std::ostream& operator<<(std::ostream& o,
                                       const dbg_threadid_t& t) {
  o << t.pid << "." << t.tid;
  return o;
}

static const dbg_threadid_t DBG_ANY_THREAD = { 0, 0 };
static const dbg_threadid_t DBG_ALL_THREADS = { -1, -1 };

static const size_t DBG_MAX_REG_SIZE = 16;

/**
 * Represents a possibly-undefined register |name|.  |size| indicates how
 * many bytes of |value| are valid, if any.
 */
struct DbgRegister {
  DebuggerRegister name;
  uint8_t value[DBG_MAX_REG_SIZE];
  size_t size;
  bool defined;
};

/**
 * Represents the register file, indexed by |DbgRegister| values
 * above.
 */
struct DbgRegfile {
  std::vector<DbgRegister> regs;

  DbgRegfile(size_t n_regs) : regs(n_regs) {};

  size_t total_registers() const { return regs.size(); }
};

enum DbgRequestType {
  DREQ_NONE = 0,

  /* None of these requests have parameters. */
  DREQ_GET_CURRENT_THREAD,
  DREQ_GET_OFFSETS,
  DREQ_GET_REGS,
  DREQ_GET_STOP_REASON,
  DREQ_GET_THREAD_LIST,

  /* These use params.target. */
  DREQ_GET_AUXV,
  DREQ_GET_IS_THREAD_ALIVE,
  DREQ_GET_THREAD_EXTRA_INFO,
  DREQ_SET_CONTINUE_THREAD,
  DREQ_SET_QUERY_THREAD,

  /* These use params.mem. */
  DREQ_GET_MEM,
  DREQ_SET_MEM,
  DREQ_REMOVE_SW_BREAK,
  DREQ_REMOVE_HW_BREAK,
  DREQ_REMOVE_WR_WATCH,
  DREQ_REMOVE_RD_WATCH,
  DREQ_REMOVE_RDWR_WATCH,
  DREQ_SET_SW_BREAK,
  DREQ_SET_HW_BREAK,
  DREQ_SET_WR_WATCH,
  DREQ_SET_RD_WATCH,
  DREQ_SET_RDWR_WATCH,
  DREQ_WATCH_FIRST = DREQ_REMOVE_SW_BREAK,
  DREQ_WATCH_LAST = DREQ_SET_RDWR_WATCH,

  /* Use params.reg. */
  DREQ_GET_REG,
  DREQ_SET_REG,

  /* No parameters. */
  DREQ_CONTINUE,
  DREQ_INTERRUPT,
  DREQ_STEP,

  /* gdb host detaching from stub.  No parameters. */
  DREQ_DETACH,

  /* Uses params.restart. */
  DREQ_RESTART,

  // gdb wants to read the current siginfo_t for a stopped
  // tracee.  More importantly, this packet arrives at the very
  // beginning of a |call foo()| experiment.
  //
  // Uses .mem for offset/len.
  DREQ_READ_SIGINFO,

  // gdb wants to write back siginfo_t to a tracee.  More
  // importantly, this packet arrives before an experiment
  // session for a |call foo()| is about to be torn down.
  //
  // TODO: actual interface NYI.
  DREQ_WRITE_SIGINFO,
};

enum DbgRestartType {
  RESTART_FROM_PREVIOUS,
  RESTART_FROM_EVENT,
  RESTART_FROM_CHECKPOINT,
};

/**
 * These requests are made by the debugger host and honored in proxy
 * by rr, the target.
 */
struct dbg_request {
  DbgRequestType type;

  dbg_threadid_t target;

  bool suppress_debugger_stop;

  union {
    struct {
      void* addr;
      size_t len;
      // For SET_MEM requests, the stream of |len|
      // number of raw bytes that are to be written.
      const uint8_t* data;
    } mem;

    DbgRegister reg;

    struct {
      int param;
      DbgRestartType type;
    } restart;
  };
};

/**
 * An item in a process's auxiliary vector, for example { AT_SYSINFO,
 * 0xb7fff414 }.
 */
struct dbg_auxv_pair {
  long key;
  long value;
};

/**
 * Return nonzero if |req| requires that program execution be resumed
 * in some way.
 */
bool dbg_is_resume_request(const struct dbg_request* req);

/**
 * Wait for exactly one gdb host to connect to this remote target on
 * IP address |addr|, port |port|.  If |probe| is nonzero, a unique
 * port based on |start_port| will be searched for.  Otherwise, if
 * |port| is already bound, this function will fail.
 *
 * Pass the |tgid| of the task on which this debug-connection request
 * is being made.  The remaining debugging session will be limited to
 * traffic regarding |tgid|, but clients don't need to and shouldn't
 * need to assume that.
 *
 * If we're opening this connection on behalf of a known client, past
 * its pid as |client| and its |client_params_fd|.  |exe_image| is the
 * process that will be debugged by client, or null ptr if there isn't
 * a client.
 *
 * This function is infallible: either it will return a valid
 * debugging context, or it won't return.
 */
enum {
  DONT_PROBE = 0,
  PROBE_PORT
};
struct dbg_context* dbg_await_client_connection(const char* addr,
                                                unsigned short desired_port,
                                                int probe, pid_t tgid,
                                                const char* exe_image = nullptr,
                                                pid_t client = -1,
                                                int client_params_fd = -1);

/**
 * Launch a debugger using the params that were written to
 * |params_pipe_fd|.  Optionally, pre-define in the gdb client the set
 * of macros defined in |macros| if nonnull.
 */
void dbg_launch_debugger(int params_pipe_fd, const char* macros);

/**
 * Call this when the target of |req| is needed to fulfill the
 * request, but the target is dead.  This situation is a symptom of a
 * gdb or rr bug.
 */
void dbg_notify_no_such_thread(struct dbg_context* dbg,
                               const struct dbg_request* req);

/**
 * Return the current request made by the debugger host, that needs to
 * be satisfied.  This function will block until either there's a
 * debugger host request that needs a response, or until a request is
 * made to resume execution of the target.  In the latter case,
 * calling this function multiple times will return an appropriate
 * resume request each time (see above).
 *
 * The target should peek at the debugger request in between execution
 * steps.  A new request may need to be serviced.
 */
struct dbg_request dbg_get_request(struct dbg_context* dbg);

/**
 * Notify the host that this process has exited with |code|.
 */
void dbg_notify_exit_code(struct dbg_context* dbg, int code);

/**
 * Notify the host that this process has exited from |sig|.
 */
void dbg_notify_exit_signal(struct dbg_context* dbg, int sig);

/**
 * Notify the host that a resume request has "finished", i.e., the
 * target has stopped executing for some reason.  |sig| is the signal
 * that stopped execution, or 0 if execution stopped otherwise.
 */
void dbg_notify_stop(struct dbg_context* dbg, dbg_threadid_t which, int sig,
                     void* watch_addr = nullptr);

/** Notify the debugger that a restart request failed. */
void dbg_notify_restart_failed(struct dbg_context* dbg);

/**
 * Tell the host that |thread| is the current thread.
 */
void dbg_reply_get_current_thread(struct dbg_context* dbg,
                                  dbg_threadid_t thread);

/**
 * Reply with the target thread's |auxv| containing |len| pairs, or
 * |len| <= 0 if there was an error reading the auxiliary vector.
 */
void dbg_reply_get_auxv(struct dbg_context* dbg,
                        const struct dbg_auxv_pair* auxv, ssize_t len);

/**
 * |alive| is nonzero if the requested thread is alive, zero if dead.
 */
void dbg_reply_get_is_thread_alive(struct dbg_context* dbg, int alive);

/**
 * |info| is a string containing data about the request target that
 * might be relevant to the debugger user.
 */
void dbg_reply_get_thread_extra_info(struct dbg_context* dbg, const char* info);

/**
 * |ok| is nonzero if req->target can be selected, zero otherwise.
 */
void dbg_reply_select_thread(struct dbg_context* dbg, int ok);

/**
 * The first |len| bytes of the request were read into |mem|.  |len|
 * must be less than or equal to the length of the request.
 */
void dbg_reply_get_mem(struct dbg_context* dbg, const uint8_t* mem, size_t len);

/**
 * |ok| is true if a SET_MEM request succeeded, false otherwise.  This
 * function *must* be called whenever a SET_MEM request is made,
 * regardless of success/failure or special interpretation.
 */
void dbg_reply_set_mem(struct dbg_context* dbg, int ok);

/**
 * Reply to the DREQ_GET_OFFSETS request.
 */
void dbg_reply_get_offsets(struct dbg_context* dbg /*, TODO */);

/**
 * Send |value| back to the debugger host.  |value| may be undefined.
 */
void dbg_reply_get_reg(struct dbg_context* dbg, const DbgRegister& value);

/**
 * Send |file| back to the debugger host.  |file| may contain
 * undefined register values.
 */
void dbg_reply_get_regs(struct dbg_context* dbg, const DbgRegfile& file);

/**
 * Pass |ok = true| iff the requested register was successfully set.
 */
void dbg_reply_set_reg(struct dbg_context* dbg, bool ok);

/**
 * Reply to the DREQ_GET_STOP_REASON request.
 */
void dbg_reply_get_stop_reason(struct dbg_context* dbg, dbg_threadid_t which,
                               int sig);

/**
 * |threads| contains the list of live threads, of which there are
 * |len|.
 */
void dbg_reply_get_thread_list(struct dbg_context* dbg,
                               const dbg_threadid_t* threads, ssize_t len);

/**
 * |code| is 0 if the request was successfully applied, nonzero if
 * not.
 */
void dbg_reply_watchpoint_request(struct dbg_context* dbg, int code);

/**
 * DREQ_DETACH was processed.
 *
 * There's no functional reason to reply to the detach request.
 * However, some versions of gdb expect a response and time out
 * awaiting it, wasting developer time.
 */
void dbg_reply_detach(struct dbg_context* dbg);

/**
 * Pass the siginfo_t and its size (as requested by the debugger) in
 * |si_bytes| and |num_bytes| if successfully read.  Otherwise pass
 * |si_bytes = NULL|.
 */
void dbg_reply_read_siginfo(struct dbg_context* dbg, const uint8_t* si_bytes,
                            ssize_t num_bytes);
/**
 * Not yet implemented, but call this after a WRITE_SIGINFO request
 * anyway.
 */
void dbg_reply_write_siginfo(struct dbg_context* dbg /*, TODO*/);

/**
 * Create a checkpoint of the given Session with the given id. Delete the
 * existing checkpoint with that id if there is one.
 */
void dbg_created_checkpoint(struct dbg_context* dbg,
                            ReplaySession::shr_ptr& checkpoint,
                            int checkpoint_id);

/**
 * Delete the checkpoint with the given id. Silently fail if the checkpoint
 * does not exist.
 */
void dbg_delete_checkpoint(struct dbg_context* dbg, int checkpoint_id);

/**
 * Get the checkpoint with the given id. Return null if not found.
 */
ReplaySession::shr_ptr dbg_get_checkpoint(struct dbg_context* dbg,
                                          int checkpoint_id);

/**
 * Destroy a gdb debugging context created by
 * |dbg_await_client_connection()|.  It's legal to pass a null |*dbg|.
 * The passed-in outparam is nulled on return.
 */
void dbg_destroy_context(struct dbg_context** dbg);

#endif /* DBG_GDB_G_ */
