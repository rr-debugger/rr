/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_RECORD_SESSION_H_
#define RR_RECORD_SESSION_H_

#include "Session.h"

/** Encapsulates additional session state related to recording. */
class RecordSession : public Session {
public:
  typedef std::shared_ptr<RecordSession> shr_ptr;

  /**
   * Fork and exec the initial tracee task, and return it.
   */
  Task* create_task();

  TraceWriter& trace_writer() { return trace_out; }

  /**
   * Create a recording session for the initial exe image
   * |exe_path|.  (That argument is used to name the trace
   * directory.)
   */
  static shr_ptr create(const std::vector<std::string>& argv,
                        const std::vector<std::string>& envp,
                        const std::string& cwd, int bind_to_cpu);

  virtual RecordSession* as_record() { return this; }

  virtual TraceStream& trace() { return trace_out; }

private:
  RecordSession(const std::vector<std::string>& argv,
                const std::vector<std::string>& envp, const std::string& cwd,
                int bind_to_cpu);

  TraceWriter trace_out;
};

#endif // RR_RECORD_SESSION_H_
