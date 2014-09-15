/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_TRACE_H_
#define RR_TRACE_H_

#include <unistd.h>

#include <memory>
#include <string>
#include <vector>

#include "CompressedReader.h"
#include "CompressedWriter.h"
#include "Event.h"
#include "remote_ptr.h"
#include "TraceFrame.h"
#include "TraceMappedRegion.h"

/**
 * TraceFstream stores all the data common to both recording and
 * replay.  TraceOfstream deals with recording-specific logic, and
 * TraceIfstream handles replay-specific details.
 */
class TraceStream {
protected:
  typedef std::string string;

public:
  /** Return the directory storing this trace's files. */
  const string& dir() const { return trace_dir; }

  const string& initial_exe() const { return argv[0]; }
  const std::vector<string>& initial_argv() const { return argv; }
  const std::vector<string>& initial_envp() const { return envp; }
  const string& initial_cwd() const { return cwd; }
  int bound_to_cpu() const { return bind_to_cpu; }

  /**
   * Return the current "global time" (event count) for this
   * trace.
   */
  TraceFrame::Time time() const { return global_time; }

protected:
  TraceStream(const string& trace_dir, TraceFrame::Time initial_time)
      : trace_dir(trace_dir), global_time(initial_time) {}

  string events_path() const { return trace_dir + "/events"; }
  string data_path() const { return trace_dir + "/data"; }
  string data_header_path() const { return trace_dir + "/data_header"; }
  string mmaps_path() const { return trace_dir + "/mmaps"; }
  /**
   * Return the path of the "args_env" file, into which the
   * initial tracee argv and envp are recorded.
   */
  string args_env_path() const { return trace_dir + "/args_env"; }
  /**
   * Return the path of "version" file, into which the current
   * trace format version of rr is stored upon creation of the
   * trace.
   */
  string version_path() const { return trace_dir + "/version"; }

  /**
   * Increment the global time and return the incremented value.
   */
  void tick_time() { ++global_time; }

  // Directory into which we're saving the trace files.
  string trace_dir;
  // The initial argv and envp for a tracee.
  std::vector<string> argv;
  std::vector<string> envp;
  // Current working directory at start of record/replay.
  string cwd;
  // CPU core# that the tracees are bound to
  int bind_to_cpu;

  // Arbitrary notion of trace time, ticked on the recording of
  // each event (trace frame).
  TraceFrame::Time global_time;
};

class TraceWriter : public TraceStream {
public:
  /**
   * Write relevant data to the trace.
   *
   * Recording a trace frame has the side effect of ticking
   * the global time.
   */
  friend TraceWriter& operator<<(TraceWriter& tif, const TraceFrame& frame);
  friend TraceWriter& operator<<(TraceWriter& tif,
                                 const TraceMappedRegion& map);

  /**
   * Write a raw-data record to the trace.
   * 'addr' is the address in the tracee where the data came from/will be
   * restored to.
   */
  void write_raw(const void* data, size_t len, remote_ptr<void> addr);

  /**
   * Return true iff all trace files are "good".
   */
  bool good() const;

  /** Call close() on all the relevant trace files.
   *  Normally this will be called by the destructor. It's helpful to
   *  call this before a crash that won't call the destructor, to ensure
   *  buffered data is flushed.
   */
  void close();

  /**
   * Create a trace that will record the initial exe
   * image |argv[0]| with initial args |argv|, initial environment |envp|,
   * current working directory |cwd| and bound to cpu |bind_to_cpu|. This
   * data is recored in the trace.
   * The trace name is determined by the global rr args and environment.
   */
  TraceWriter(const std::vector<std::string>& argv,
              const std::vector<std::string>& envp, const string& cwd,
              int bind_to_cpu);

private:
  // File that stores events (trace frames).
  CompressedWriter events;
  // Files that store raw data saved from tracees (|data|), and
  // metadata about the stored data (|data_header|).
  CompressedWriter data;
  CompressedWriter data_header;
  // File that stores metadata about files mmap'd during
  // recording.
  CompressedWriter mmaps;
};

class TraceReader : public TraceStream {
public:
  /**
   * A parcel of recorded tracee data.  |data| contains the data read
   * from |addr| in the tracee.
   */
  struct RawData {
    std::vector<uint8_t> data;
    remote_ptr<void> addr;
  };

  /**
   * Read relevant data from the trace.
   *
   * NB: reading a trace frame has the side effect of ticking
   * the global time to match the time recorded in the trace
   * frame.
   */
  TraceFrame read_trace_frame();

  /**
   * Read the next mapped region descriptor and return it.
   */
  TraceMappedRegion read_mapped_region();

  /**
   * Read the next raw data record and return it.
   */
  RawData read_raw_data();

  /**
   * Reads the next raw data record for 'frame' from the current point in
   * the trace. If there are no more raw data records for 'frame', returns
   * false.
   */
  bool read_raw_data_for_frame(const TraceFrame& frame, RawData& d);

  /**
   * Return true iff all trace files are "good".
   * for more details.
   */
  bool good() const;

  /**
   * Return true if we're at the end of the trace file.
   */
  bool at_end() const { return events.at_end(); }

  /**
   * Return the next trace frame, without mutating any stream
   * state.
   */
  TraceFrame peek_frame();

  /**
   * Peek ahead in the stream to find the next trace frame that
   * matches the requested parameters. Returns the frame if one
   * was found, and issues a fatal error if not.
   */
  TraceFrame peek_to(pid_t pid, EventType type, SyscallEntryOrExit state);

  /**
   * Restore the state of this to what it was just after
   * |open()|.
   */
  void rewind();

  uint64_t uncompressed_bytes() const;
  uint64_t compressed_bytes() const;

  /**
   * Open the trace in 'dir'. When 'dir' is the empty string, open the
   * latest trace.
   */
  TraceReader(const string& dir = string());

  /**
   * Create a copy of this stream that has exactly the same
   * state as 'other', but for which mutations of this
   * clone won't affect the state of 'other' (and vice versa).
   */
  TraceReader(const TraceReader& other)
      : TraceStream(other.dir(), other.time()),
        events(other.events),
        data(other.data),
        data_header(other.data_header),
        mmaps(other.mmaps) {
    argv = other.argv;
    envp = other.envp;
    cwd = other.cwd;
    bind_to_cpu = other.bind_to_cpu;
  }

private:
  // File that stores events (trace frames).
  CompressedReader events;
  // Files that store raw data saved from tracees (|data|), and
  // metadata about the stored data (|data_header|).
  CompressedReader data;
  CompressedReader data_header;
  // File that stores metadata about files mmap'd during
  // recording.
  CompressedReader mmaps;
};

#endif /* RR_TRACE_H_ */
