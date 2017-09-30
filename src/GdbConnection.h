/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_GDB_CONNECTION_H_
#define RR_GDB_CONNECTION_H_

#include <stddef.h>
#include <sys/types.h>

#include <memory>
#include <ostream>
#include <string>
#include <vector>

#include "GdbRegister.h"
#include "Registers.h"
#include "ReplaySession.h"
#include "ReplayTimeline.h"
#include "core.h"

namespace rr {

/**
 * Descriptor for task.  Note: on linux, we can uniquely identify any thread
 * by its |tid| (in rr's pid namespace).
 */
struct GdbThreadId {
  GdbThreadId(pid_t pid = -1, pid_t tid = -1) : pid(pid), tid(tid) {}

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
  enum { MAX_SIZE = Registers::MAX_SIZE };
  GdbRegister name;
  union {
    uint8_t value[MAX_SIZE];
    uint8_t value1;
    uint16_t value2;
    uint32_t value4;
    uint64_t value8;
  };
  size_t size;
  bool defined;
};

enum GdbRequestType {
  DREQ_NONE = 0,

  /* None of these requests have parameters. */
  DREQ_GET_CURRENT_THREAD,
  DREQ_GET_OFFSETS,
  DREQ_GET_REGS,
  DREQ_GET_STOP_REASON,
  DREQ_GET_THREAD_LIST,
  DREQ_INTERRUPT,
  DREQ_DETACH,

  /* These use params.target. */
  DREQ_GET_AUXV,
  DREQ_GET_EXEC_FILE,
  DREQ_GET_IS_THREAD_ALIVE,
  DREQ_GET_THREAD_EXTRA_INFO,
  DREQ_SET_CONTINUE_THREAD,
  DREQ_SET_QUERY_THREAD,
  // TLS lookup, uses params.target and params.tls.
  DREQ_TLS,
  // gdb wants to write back siginfo_t to a tracee.  More
  // importantly, this packet arrives before an experiment
  // session for a |call foo()| is about to be torn down.
  //
  // TODO: actual interface NYI.
  DREQ_WRITE_SIGINFO,

  /* These use params.mem. */
  DREQ_GET_MEM,
  DREQ_SET_MEM,
  // gdb wants to read the current siginfo_t for a stopped
  // tracee.  More importantly, this packet arrives at the very
  // beginning of a |call foo()| experiment.
  //
  // Uses .mem for offset/len.
  DREQ_READ_SIGINFO,
  DREQ_SEARCH_MEM,
  DREQ_MEM_FIRST = DREQ_GET_MEM,
  DREQ_MEM_LAST = DREQ_SEARCH_MEM,

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
  DREQ_REG_FIRST = DREQ_GET_REG,
  DREQ_REG_LAST = DREQ_SET_REG,

  /* Use params.cont. */
  DREQ_CONT,

  /* gdb host detaching from stub.  No parameters. */

  /* Uses params.restart. */
  DREQ_RESTART,

  /* Uses params.text. */
  DREQ_RR_CMD,

  // qSymbol packet, uses params.sym.
  DREQ_QSYMBOL,

  // vFile:setfs packet, uses params.file_setfs.
  DREQ_FILE_SETFS,
  // vFile:open packet, uses params.file_open.
  DREQ_FILE_OPEN,
  // vFile:pread packet, uses params.file_pread.
  DREQ_FILE_PREAD,
  // vFile:close packet, uses params.file_close.
  DREQ_FILE_CLOSE,
};

enum GdbRestartType {
  RESTART_FROM_PREVIOUS,
  RESTART_FROM_EVENT,
  RESTART_FROM_CHECKPOINT,
};

enum GdbActionType { ACTION_CONTINUE, ACTION_STEP };

struct GdbContAction {
  GdbContAction(GdbActionType type = ACTION_CONTINUE,
                const GdbThreadId& target = GdbThreadId::ANY,
                int signal_to_deliver = 0)
      : type(type), target(target), signal_to_deliver(signal_to_deliver) {}
  GdbActionType type;
  GdbThreadId target;
  int signal_to_deliver;
};

/**
 * These requests are made by the debugger host and honored in proxy
 * by rr, the target.
 */
struct GdbRequest {
  GdbRequest(GdbRequestType type = DREQ_NONE)
      : type(type), suppress_debugger_stop(false) {}
  GdbRequest(const GdbRequest& other)
      : type(other.type),
        target(other.target),
        suppress_debugger_stop(other.suppress_debugger_stop),
        mem_(other.mem_),
        watch_(other.watch_),
        reg_(other.reg_),
        restart_(other.restart_),
        cont_(other.cont_),
        text_(other.text_),
        tls_(other.tls_),
        sym_(other.sym_),
        file_setfs_(other.file_setfs_),
        file_open_(other.file_open_),
        file_pread_(other.file_pread_),
        file_close_(other.file_close_) {}
  GdbRequest& operator=(const GdbRequest& other) {
    this->~GdbRequest();
    new (this) GdbRequest(other);
    return *this;
  }

  const GdbRequestType type;
  GdbThreadId target;
  bool suppress_debugger_stop;

  struct Mem {
    uintptr_t addr;
    size_t len;
    // For SET_MEM requests, the |len| raw bytes that are to be written.
    // For SEARCH_MEM requests, the bytes to search for.
    std::vector<uint8_t> data;
  } mem_;
  struct Watch {
    uintptr_t addr;
    int kind;
    std::vector<std::vector<uint8_t>> conditions;
  } watch_;
  GdbRegisterValue reg_;
  struct Restart {
    int param;
    std::string param_str;
    GdbRestartType type;
  } restart_;
  struct Cont {
    RunDirection run_direction;
    std::vector<GdbContAction> actions;
  } cont_;
  std::string text_;
  struct Tls {
    size_t offset;
    remote_ptr<void> load_module;
  } tls_;
  struct Symbol {
    bool has_address;
    remote_ptr<void> address;
    std::string name;
  } sym_;
  struct FileSetfs {
    pid_t pid;
  } file_setfs_;
  struct FileOpen {
    std::string file_name;
    // In system format, not gdb's format
    int flags;
    int mode;
  } file_open_;
  struct FilePread {
    int fd;
    size_t size;
    uint64_t offset;
  } file_pread_;
  struct FileClose {
    int fd;
  } file_close_;

  Mem& mem() {
    DEBUG_ASSERT(type >= DREQ_MEM_FIRST && type <= DREQ_MEM_LAST);
    return mem_;
  }
  const Mem& mem() const {
    DEBUG_ASSERT(type >= DREQ_MEM_FIRST && type <= DREQ_MEM_LAST);
    return mem_;
  }
  Watch& watch() {
    DEBUG_ASSERT(type >= DREQ_WATCH_FIRST && type <= DREQ_WATCH_LAST);
    return watch_;
  }
  const Watch& watch() const {
    DEBUG_ASSERT(type >= DREQ_WATCH_FIRST && type <= DREQ_WATCH_LAST);
    return watch_;
  }
  GdbRegisterValue& reg() {
    DEBUG_ASSERT(type >= DREQ_REG_FIRST && type <= DREQ_REG_LAST);
    return reg_;
  }
  const GdbRegisterValue& reg() const {
    DEBUG_ASSERT(type >= DREQ_REG_FIRST && type <= DREQ_REG_LAST);
    return reg_;
  }
  Restart& restart() {
    DEBUG_ASSERT(type == DREQ_RESTART);
    return restart_;
  }
  const Restart& restart() const {
    DEBUG_ASSERT(type == DREQ_RESTART);
    return restart_;
  }
  Cont& cont() {
    DEBUG_ASSERT(type == DREQ_CONT);
    return cont_;
  }
  const Cont& cont() const {
    DEBUG_ASSERT(type == DREQ_CONT);
    return cont_;
  }
  const std::string& text() const {
    DEBUG_ASSERT(type == DREQ_RR_CMD);
    return text_;
  }
  Tls& tls() {
    DEBUG_ASSERT(type == DREQ_TLS);
    return tls_;
  }
  const Tls& tls() const {
    DEBUG_ASSERT(type == DREQ_TLS);
    return tls_;
  }
  Symbol& sym() {
    DEBUG_ASSERT(type == DREQ_QSYMBOL);
    return sym_;
  }
  const Symbol& sym() const {
    DEBUG_ASSERT(type == DREQ_QSYMBOL);
    return sym_;
  }
  FileSetfs& file_setfs() {
    DEBUG_ASSERT(type == DREQ_FILE_SETFS);
    return file_setfs_;
  }
  const FileSetfs& file_setfs() const {
    DEBUG_ASSERT(type == DREQ_FILE_SETFS);
    return file_setfs_;
  }
  FileOpen& file_open() {
    DEBUG_ASSERT(type == DREQ_FILE_OPEN);
    return file_open_;
  }
  const FileOpen& file_open() const {
    DEBUG_ASSERT(type == DREQ_FILE_OPEN);
    return file_open_;
  }
  FilePread& file_pread() {
    DEBUG_ASSERT(type == DREQ_FILE_PREAD);
    return file_pread_;
  }
  const FilePread& file_pread() const {
    DEBUG_ASSERT(type == DREQ_FILE_PREAD);
    return file_pread_;
  }
  FileClose& file_close() {
    DEBUG_ASSERT(type == DREQ_FILE_CLOSE);
    return file_close_;
  }
  const FileClose& file_close() const {
    DEBUG_ASSERT(type == DREQ_FILE_CLOSE);
    return file_close_;
  }

  /**
   * Return nonzero if this requires that program execution be resumed
   * in some way.
   */
  bool is_resume_request() const { return type == DREQ_CONT; }
};

/**
 * This struct wraps up the state of the gdb protocol, so that we can
 * offer a (mostly) stateless interface to clients.
 */
class GdbConnection {
public:
  struct Features {
    Features() : reverse_execution(true) {}
    bool reverse_execution;
  };

  /**
   * Call this when the target of |req| is needed to fulfill the
   * request, but the target is dead.  This situation is a symptom of a
   * gdb or rr bug.
   */
  void notify_no_such_thread(const GdbRequest& req);

  /**
   * Finish a DREQ_RESTART request.  Should be invoked after replay
   * restarts and prior GdbConnection has been restored.
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
   * Reply with the target thread's |auxv| pairs. |auxv.empty()|
   * if there was an error reading the auxiliary vector.
   */
  void reply_get_auxv(const std::vector<uint8_t>& auxv);

  /**
   * Reply with the target thread's executable file name
   */
  void reply_get_exec_file(const std::string& exec_file);

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
   * Reply to the DREQ_SEARCH_MEM request.
   * |found| is true if we found the searched-for bytes starting at address
   * |addr|.
   */
  void reply_search_mem(bool found, remote_ptr<void> addr);

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
  void reply_get_regs(const std::vector<GdbRegisterValue>& file);

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
  void reply_get_thread_list(const std::vector<GdbThreadId>& threads);

  /**
   * |ok| is true if the request was successfully applied, false if
   * not.
   */
  void reply_watchpoint_request(bool ok);

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
  void reply_read_siginfo(const std::vector<uint8_t>& si_bytes);
  /**
   * Not yet implemented, but call this after a WRITE_SIGINFO request
   * anyway.
   */
  void reply_write_siginfo(/* TODO*/);

  /**
   * Send a manual text response to a rr cmd (maintenance) packet.
   */
  void reply_rr_cmd(const std::string& text);

  /**
   * Send a qSymbol response to gdb, requesting the address of the
   * symbol |name|.
   */
  void send_qsymbol(const std::string& name);

  /**
   * The "all done" response to a qSymbol packet from gdb.
   */
  void qsymbols_finished();

  /**
   * Respond to a qGetTLSAddr packet.  If |ok| is true, then respond
   * with |address|.  If |ok| is false, respond with an error.
   */
  void reply_tls_addr(bool ok, remote_ptr<void> address);

  /**
   * Respond to a vFile:setfs
   */
  void reply_setfs(int err);
  /**
   * Respond to a vFile:open
   */
  void reply_open(int fd, int err);
  /**
   * Respond to a vFile:pread
   */
  void reply_pread(const uint8_t* bytes, ssize_t len, int err);
  /**
   * Respond to a vFile:close
   */
  void reply_close(int err);

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

  /**
   * Return true if there's a new packet to be read/process (whether
   * incomplete or not), and false if there isn't one.
   */
  bool sniff_packet();

  const Features& features() { return features_; }

  enum {
    CPU_64BIT = 0x1,
    CPU_AVX = 0x2,
  };
  void set_cpu_features(uint32_t features) { cpu_features_ = features; }
  uint32_t cpu_features() const { return cpu_features_; }

  GdbConnection(pid_t tgid, const Features& features);

  /**
   * Wait for a debugger client to connect to |dbg|'s socket.  Blocks
   * indefinitely.
   */
  void await_debugger(ScopedFd& listen_fd);

  /**
   *  Returns false if the connection has been closed
  */
  bool is_connection_alive();

private:
  /**
   * read() incoming data exactly one time, successfully.  May block.
   */
  void read_data_once();
  /**
   * Send all pending output to gdb.  May block.
   */
  void write_flush();
  void write_data_raw(const uint8_t* data, ssize_t len);
  void write_hex(unsigned long hex);
  void write_packet_bytes(const uint8_t* data, size_t num_bytes);
  void write_packet(const char* data);
  void write_binary_packet(const char* pfx, const uint8_t* data,
                           ssize_t num_bytes);
  void write_hex_bytes_packet(const char* prefix, const uint8_t* bytes,
                              size_t len);
  void write_hex_bytes_packet(const uint8_t* bytes, size_t len);
  void write_xfer_response(const void* data, size_t size, uint64_t offset,
                           uint64_t len);
  /**
   * Consume bytes in the input buffer until start-of-packet ('$') or
   * the interrupt character is seen.  Does not block.  Return true if
   * seen, false if not.
   */
  bool skip_to_packet_start();
  /**
   * Block until the sequence of bytes
   *
   *    "[^$]*\$[^#]*#.*"
   *
   * has been read from the client fd.  This is one (or more) gdb
   * packet(s).
   */
  void read_packet();
  /**
   * Return true if we need to do something in a debugger request,
   * false if we already handled the packet internally.
   */
  bool xfer(const char* name, char* args);
  /**
   * Return true if we need to do something in a debugger request,
   * false if we already handled the packet internally.
   */
  bool query(char* payload);
  /**
   * Return true if we need to do something in a debugger request,
   * false if we already handled the packet internally.
   */
  bool set_var(char* payload);
  /**
   * Return true if we need to do something in a debugger request,
   * false if we already handled the packet internally.
   */
  bool process_vpacket(char* payload);
  /**
   * Return true if we need to do something in a debugger request,
   * false if we already handled the packet internally.
   */
  bool process_bpacket(char* payload);
  /**
   * Return true if we need to do something in a debugger request,
   * false if we already handled the packet internally.
   */
  bool process_packet();
  void consume_request();
  void send_stop_reply_packet(GdbThreadId thread, int sig,
                              uintptr_t watch_addr = 0);
  void send_file_error_reply(int system_errno);

  // Current request to be processed.
  GdbRequest req;
  // Thread to be resumed.
  GdbThreadId resume_thread;
  // Thread for get/set requests.
  GdbThreadId query_thread;
  // gdb and rr don't work well together in multi-process and
  // multi-exe-image debugging scenarios, so we pretend only
  // this thread group exists when interfacing with gdb
  pid_t tgid;
  uint32_t cpu_features_;
  // true when "no-ack mode" enabled, in which we don't have
  // to send ack packets back to gdb.  This is a huge perf win.
  bool no_ack;
  ScopedFd sock_fd;
  std::vector<uint8_t> inbuf;  /* buffered input from gdb */
  size_t packetend;            /* index of '#' character */
  std::vector<uint8_t> outbuf; /* buffered output for gdb */
  Features features_;
  bool connection_alive_;
};

} // namespace rr

#endif /* RR_GDB_CONNECTION_H_ */
