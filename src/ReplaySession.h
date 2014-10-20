/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_REPLAY_SESSION_H_
#define RR_REPLAY_SESSION_H_

#include "CPUIDBugDetector.h"
#include "EmuFs.h"
#include "replayer.h"
#include "Session.h"

struct syscallbuf_hdr;

/** Encapsulates additional session state related to replay. */
class ReplaySession : public Session {
public:
  typedef std::shared_ptr<ReplaySession> shr_ptr;

  ~ReplaySession();

  /**
   * Return a semantic copy of all the state managed by this,
   * that is the entire tracee tree and the state it depends on.
   * Any mutations of the returned Session can't affect the
   * state of this, and vice versa.
   *
   * This operation is also called "checkpointing" the replay
   * session.
   */
  shr_ptr clone();

  /**
   * Like |clone()|, but return a session in "diversion" mode,
   * which allows free execution.  The returned session has
   * exactly one ref().  See diversioner.h.
   */
  shr_ptr clone_diversion();

  /**
   * Fork and exec the initial tracee task to run |ae|, and read
   * recorded events from |trace|.  |rec_tid| is the recorded
   * tid of the initial tracee task.  Return that Task.
   */
  Task* create_task(pid_t rec_tid);

  EmuFs& emufs() { return *emu_fs; }

  /** Collect garbage files from this session's emufs. */
  void gc_emufs();

  TraceReader& trace_reader() { return trace_in; }

  /**
   * True when this diversion is dying, as determined by
   * clients.
   */
  bool diversion_dying() const {
    assert(is_diversion);
    return 0 == diversion_refcount;
  }

  /**
   * True when this is an diversion session; see diversioner.h.
   */
  bool diversion() const { return is_diversion; }

  /**
   * The trace record that we are working on --- the next event
   * for replay to reach.
   */
  TraceFrame& current_trace_frame() { return trace_frame; }
  /**
   * State of the replay as we advance towards the event given by
   * current_trace_frame().
   */
  struct rep_trace_step& current_replay_step() { return replay_step; }

  uint8_t* syscallbuf_flush_buffer() { return syscallbuf_flush_buffer_array; }
  const struct syscallbuf_hdr* syscallbuf_flush_buffer_hdr() {
    return (const struct syscallbuf_hdr*)syscallbuf_flush_buffer_array;
  }

  bool& reached_trace_frame() { return trace_frame_reached; }

  /**
   * Set |tgid| as the one that's being debugged in this
   * session.
   *
   * Little hack: technically replayer doesn't know about the
   * fact that debugger_gdb hides all but one tgid from the gdb
   * client.  But to recognize the last_task below (another
   * little hack), we need to known when an exiting thread from
   * the target task group is the last.
   */
  void set_debugged_tgid(pid_t tgid) {
    assert(0 == tgid_debugged);
    tgid_debugged = tgid;
  }
  pid_t debugged_tgid() const { return tgid_debugged; }

  /**
   * Set |t| as the last (debugged) task in this session.
   *
   * When we notify the debugger of process exit, it wants to be
   * able to poke around at that last task.  So we store it here
   * to allow processing debugger requests for it later.
   */
  void set_last_task(Task* t) {
    assert(!last_debugged_task);
    last_debugged_task = t;
  }
  Task* last_task() { return last_debugged_task; }

  /**
   * Add another reference to this diversion, which specifically
   * means another call to |diversion_unref()| must be made
   * before this is considered to be dying.
   */
  void diversion_ref() {
    assert(is_diversion);
    assert(diversion_refcount >= 0);
    ++diversion_refcount;
  }

  /**
   * Remove a reference to this diversion created by
   * |diversion_ref()|.
   */
  void diversion_unref() {
    assert(is_diversion);
    assert(diversion_refcount > 0);
    --diversion_refcount;
  }

  /**
   * Create a replay session that will use the trace specified
   * by the commad-line args |argc|/|argv|.  Return it.
   */
  static shr_ptr create(int argc, char* argv[]);

  CPUIDBugDetector& bug_detector() { return cpuid_bug_detector; }

  virtual ReplaySession* as_replay() override { return this; }

  virtual TraceStream& trace() override { return trace_in; }

private:
  ReplaySession(const std::string& dir)
      : diversion_refcount(0),
        is_diversion(false),
        last_debugged_task(nullptr),
        tgid_debugged(0),
        trace_in(dir),
        trace_frame(),
        replay_step(),
        trace_frame_reached(false) {}

  ReplaySession(const ReplaySession& other)
      : diversion_refcount(0),
        is_diversion(false),
        last_debugged_task(nullptr),
        tgid_debugged(0),
        trace_in(other.trace_in),
        trace_frame(),
        replay_step(),
        trace_frame_reached(false) {}

  std::shared_ptr<EmuFs> emu_fs;
  // Number of client references to this, if it's a diversion
  // session.  When there are 0 refs this is considered to be
  // dying.
  int diversion_refcount;
  // True when this is an "diversion" session; see
  // diversioner.h.  In the future, this will be a separate
  // DiversionSession class.
  bool is_diversion;
  Task* last_debugged_task;
  pid_t tgid_debugged;
  TraceReader trace_in;
  TraceFrame trace_frame;
  struct rep_trace_step replay_step;
  CPUIDBugDetector cpuid_bug_detector;
  /**
   * Buffer for recorded syscallbuf bytes.  By definition buffer flushes
   * must be replayed sequentially, so we can use one buffer for all
   * tracees.  At the start of the flush, the recorded bytes are read
   * back into this buffer.  Then they're copied back to the tracee
   * record-by-record, as the tracee exits those syscalls.
   * This needs to be word-aligned.
   */
  uint8_t syscallbuf_flush_buffer_array[SYSCALLBUF_BUFFER_SIZE];
  /**
   * True when the session has reached the state in trace_frame.
   * False when the session is working towards the state in trace_frame.
   */
  bool trace_frame_reached;
};

#endif // RR_REPLAY_SESSION_H_
