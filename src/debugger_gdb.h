/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_DBG_GDB_H_
#define RR_DBG_GDB_H_

#include <stddef.h>
#include <sys/types.h>

#include <memory>
#include <ostream>
#include <vector>

#include "GDBRegister.h"
#include "ReplaySession.h"

/**
 * Descriptor for task within a task group.  Note: on linux, we can
 * uniquely identify any thread by its |tid| (ignoring pid
 * namespaces).
 */
struct GdbThreadId {
  pid_t pid;
  pid_t tid;

  bool operator==(const GdbThreadId& o) const {
    return pid == o.pid && tid == o.tid;
  }

  static const GdbThreadId ANY;
  static const GdbThreadId ALL;
};

inline std::ostream& operator<<(std::ostream& o, const GdbThreadId& t) {
  o << t.pid << "." << t.tid;
  return o;
}

/**
 * Represents a possibly-undefined register |name|.  |size| indicates how
 * many bytes of |value| are valid, if any.
 */
struct GdbRegisterValue {
  enum {
    MAX_SIZE = 16
  };
  GDBRegister name;
  uint8_t value[MAX_SIZE];
  size_t size;
  bool defined;
};

/**
 * Represents the register file, indexed by |DbgRegister| values
 * above.
 */
struct GdbRegisterFile {
  std::vector<GdbRegisterValue> regs;

  GdbRegisterFile(size_t n_regs) : regs(n_regs) {};

  size_t total_registers() const { return regs.size(); }
};

enum GdbRequestType {
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

enum GdbRestartType {
  RESTART_FROM_PREVIOUS,
  RESTART_FROM_EVENT,
  RESTART_FROM_CHECKPOINT,
};

/**
 * These requests are made by the debugger host and honored in proxy
 * by rr, the target.
 */
struct GdbRequest {
  GdbRequestType type;
  GdbThreadId target;
  bool suppress_debugger_stop;
  union {
    struct {
      uintptr_t addr;
      size_t len;
      // For SET_MEM requests, the stream of |len|
      // number of raw bytes that are to be written.
      const uint8_t* data;
    } mem;

    GdbRegisterValue reg;

    struct {
      int param;
      GdbRestartType type;
    } restart;
  };

  /**
   * Return nonzero if this requires that program execution be resumed
   * in some way.
   */
  bool is_resume_request() const {
    return type == DREQ_CONTINUE || type == DREQ_STEP;
  }
};

/**
 * An item in a process's auxiliary vector, for example { AT_SYSINFO,
 * 0xb7fff414 }.
 */
struct GdbAuxvPair {
  uintptr_t key;
  uintptr_t value;
};

/**
 * This struct wraps up the state of the gdb protocol, so that we can
 * offer a (mostly) stateless interface to clients.
 */
class GdbContext {
public:
  /**
   * Wait for exactly one gdb host to connect to this remote target on
   * IP address 127.0.0.1, port |port|.  If |probe| is nonzero, a unique
   * port based on |start_port| will be searched for.  Otherwise, if
   * |port| is already bound, this function will fail.
   *
   * Pass the |tgid| of the task on which this debug-connection request
   * is being made.  The remaining debugging session will be limited to
   * traffic regarding |tgid|, but clients don't need to and shouldn't
   * need to assume that.
   *
   * If we're opening this connection on behalf of a known client, pass
   * an fd in |client_params_fd|; we'll write the allocated port and |exe_image|
   * through the fd before waiting for a connection. |exe_image| is the
   * process that will be debugged by client, or null ptr if there isn't
   * a client.
   *
   * This function is infallible: either it will return a valid
   * debugging context, or it won't return.
   */
  enum ProbePort {
    DONT_PROBE = 0,
    PROBE_PORT
  };
  static std::unique_ptr<GdbContext> await_client_connection(
      unsigned short desired_port, ProbePort probe, pid_t tgid,
      const std::string* exe_image = nullptr,
      ScopedFd* client_params_fd = nullptr);

  /**
   * Exec gdb using the params that were written to
   * |params_pipe_fd|.  Optionally, pre-define in the gdb client the set
   * of macros defined in |macros| if nonnull.
   */
  static void launch_gdb(ScopedFd& params_pipe_fd, const char* macros);

  /**
   * Call this when the target of |req| is needed to fulfill the
   * request, but the target is dead.  This situation is a symptom of a
   * gdb or rr bug.
   */
  void notify_no_such_thread(const GdbRequest* req);

  /**
   * Finish a DREQ_RESTART request.  Should be invoked after replay
   * restarts and prior GdbContext has been restored.
   */
  void notify_restart();

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
  GdbRequest get_request();

  /**
   * Notify the host that this process has exited with |code|.
   */
  void notify_exit_code(int code);

  /**
   * Notify the host that this process has exited from |sig|.
   */
  void notify_exit_signal(int sig);

  /**
   * Notify the host that a resume request has "finished", i.e., the
   * target has stopped executing for some reason.  |sig| is the signal
   * that stopped execution, or 0 if execution stopped otherwise.
   */
  void notify_stop(GdbThreadId which, int sig, uintptr_t watch_addr = 0);

  /** Notify the debugger that a restart request failed. */
  void notify_restart_failed();

  /**
   * Tell the host that |thread| is the current thread.
   */
  void reply_get_current_thread(GdbThreadId thread);

  /**
   * Reply with the target thread's |auxv| containing |len| pairs, or
   * |len| <= 0 if there was an error reading the auxiliary vector.
   */
  void reply_get_auxv(const GdbAuxvPair* auxv, ssize_t len);

  /**
   * |alive| is true if the requested thread is alive, false if dead.
   */
  void reply_get_is_thread_alive(bool alive);

  /**
   * |info| is a string containing data about the request target that
   * might be relevant to the debugger user.
   */
  void reply_get_thread_extra_info(const std::string& info);

  /**
   * |ok| is true if req->target can be selected, false otherwise.
   */
  void reply_select_thread(bool ok);

  /**
   * The first |mem.size()| bytes of the request were read into |mem|.
   * |mem.size()| must be less than or equal to the length of the request.
   */
  void reply_get_mem(const std::vector<uint8_t>& mem);

  /**
   * |ok| is true if a SET_MEM request succeeded, false otherwise.  This
   * function *must* be called whenever a SET_MEM request is made,
   * regardless of success/failure or special interpretation.
   */
  void reply_set_mem(bool ok);

  /**
   * Reply to the DREQ_GET_OFFSETS request.
   */
  void reply_get_offsets(/* TODO */);

  /**
   * Send |value| back to the debugger host.  |value| may be undefined.
   */
  void reply_get_reg(const GdbRegisterValue& value);

  /**
   * Send |file| back to the debugger host.  |file| may contain
   * undefined register values.
   */
  void reply_get_regs(const GdbRegisterFile& file);

  /**
   * Pass |ok = true| iff the requested register was successfully set.
   */
  void reply_set_reg(bool ok);

  /**
   * Reply to the DREQ_GET_STOP_REASON request.
   */
  void reply_get_stop_reason(GdbThreadId which, int sig);

  /**
   * |threads| contains the list of live threads, of which there are
   * |len|.
   */
  void reply_get_thread_list(const GdbThreadId* threads, ssize_t len);

  /**
   * |code| is 0 if the request was successfully applied, nonzero if
   * not.
   */
  void reply_watchpoint_request(int code);

  /**
   * DREQ_DETACH was processed.
   *
   * There's no functional reason to reply to the detach request.
   * However, some versions of gdb expect a response and time out
   * awaiting it, wasting developer time.
   */
  void reply_detach();

  /**
   * Pass the siginfo_t and its size (as requested by the debugger) in
   * |si_bytes| and |num_bytes| if successfully read.  Otherwise pass
   * |si_bytes = nullptr|.
   */
  void reply_read_siginfo(const uint8_t* si_bytes, ssize_t num_bytes);
  /**
   * Not yet implemented, but call this after a WRITE_SIGINFO request
   * anyway.
   */
  void reply_write_siginfo(/* TODO*/);

  /**
   * Create a checkpoint of the given Session with the given id. Delete the
   * existing checkpoint with that id if there is one.
   */
  void created_checkpoint(ReplaySession::shr_ptr& checkpoint,
                          int checkpoint_id);

  /**
   * Delete the checkpoint with the given id. Silently fail if the checkpoint
   * does not exist.
   */
  void delete_checkpoint(int checkpoint_id);

  /**
   * Get the checkpoint with the given id. Return null if not found.
   */
  ReplaySession::shr_ptr get_checkpoint(int checkpoint_id);

private:
  GdbContext(pid_t tgid);

  /**
   * Wait for a debugger client to connect to |dbg|'s socket.  Blocks
   * indefinitely.
   */
  void await_debugger(ScopedFd& listen_fd);

  /**
   * read() incoming data exactly one time, successfully.  May block.
   */
  void read_data_once();
  void write_flush();
  void write_data_raw(const uint8_t* data, ssize_t len);
  void write_hex(unsigned long hex);
  void write_packet_bytes(const uint8_t* data, size_t num_bytes);
  void write_packet(const char* data);
  void write_binary_packet(const char* pfx, const uint8_t* data,
                           ssize_t num_bytes);
  void write_hex_bytes_packet(const uint8_t* bytes, size_t len);
  /**
   * Consume bytes in the input buffer until start-of-packet ('$') or
   * the interrupt character is seen.  Does not block.  Return zero if
   * seen, nonzero if not.
   */
  int skip_to_packet_start();
  /**
   * Return zero if there's a new packet to be read/process (whether
   * incomplete or not), and nonzero if there isn't one.
   */
  int sniff_packet();
  /**
   * Block until the sequence of bytes
   *
   *    "[^$]*\$[^#]*#.*"
   *
   * has been read from the client fd.  This is one (or more) gdb
   * packet(s).
   */
  void read_packet();
  int xfer(const char* name, char* args);
  int query(char* payload);
  int set_var(char* payload);
  void consume_request();
  int process_vpacket(char* payload);
  int process_packet();
  void send_stop_reply_packet(GdbThreadId thread, int sig,
                              uintptr_t watch_addr = 0);

  // Current request to be processed.
  GdbRequest req;
  // Thread to be resumed.
  GdbThreadId resume_thread;
  // Thread for get/set requests.
  GdbThreadId query_thread;
  // gdb and rr don't work well together in multi-process and
  // multi-exe-image debugging scenarios, so we pretend only
  // this task group exists when interfacing with gdb
  pid_t tgid;
  // true when "no-ack mode" enabled, in which we don't have
  // to send ack packets back to gdb.  This is a huge perf win.
  bool no_ack;
  ScopedFd sock_fd;
  /* XXX probably need to dynamically size these */
  uint8_t inbuf[32768];  /* buffered input from gdb */
  ssize_t inlen;         /* length of valid data */
  ssize_t packetend;     /* index of '#' character */
  uint8_t outbuf[32768]; /* buffered output for gdb */
  ssize_t outlen;
};

#endif /* DBG_GDB_G_ */
