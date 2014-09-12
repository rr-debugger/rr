/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_TRACE_H_
#define RR_TRACE_H_

#include <assert.h>
#include <linux/limits.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <memory>
#include <string>
#include <vector>

#include "CompressedReader.h"
#include "CompressedWriter.h"
#include "Event.h"
#include "ExtraRegisters.h"
#include "PerfCounters.h"
#include "Registers.h"
#include "remote_ptr.h"
#include "Ticks.h"
#include "TraceFrame.h"

typedef std::vector<char*> CharpVector;

/* XXX/pedant more accurately called a "mapped /region/", since we're
 * not mapping entire files, necessarily. */
struct TraceMappedRegion {
  /* Global trace time when this region was mapped. */
  TraceFrame::Time time;
  pid_t tid;
  /* Did we save a copy of the mapped region in the trace
   * data? */
  bool copied;

  char filename[PATH_MAX];
  struct stat stat;

  /* Bounds of mapped region. */
  remote_ptr<void> start;
  remote_ptr<void> end;

  size_t size() {
    int64_t s = static_cast<uint8_t*>(static_cast<void*>(end)) -
                static_cast<uint8_t*>(static_cast<void*>(start));
    assert(s >= 0);
    return s;
  }
};

/**
 * Records data needed to supply the arguments for the |execve()| call that
 * initiates the recorded process group.
 * Also includes the current working directory at the time of the exec.
 */
struct args_env {
  args_env() {}
  args_env(int argc, char* argv[], char** envp, char* cwd, int bind_to_cpu);
  ~args_env();

  args_env& operator=(args_env&& o);

  std::string exe_image;
  std::string cwd;
  // The initial argv and envp for a tracee.  We store these as
  // the relatively complicated array of naked |char*| strings
  // so that calling |.data()| on both vectors returns a
  // |char**| that can be passed to POSIX APIs like |execve()|.
  CharpVector argv;
  CharpVector envp;
  int bind_to_cpu;

private:
  void destroy();

  args_env(const args_env&) = delete;
  args_env& operator=(const args_env&) = delete;
};

/**
 * A parcel of recorded tracee data.  |data| contains the data read
 * from |addr| in the tracee, and |ev| and |global_time| represent the
 * tracee state when the data was read.
 */
struct raw_data {
  std::vector<uint8_t> data;
  void* addr;
  EncodedEvent ev;
  uint32_t global_time;
};

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

  /**
   * Return the current "global time" (event count) for this
   * trace.
   */
  uint32_t time() const { return global_time; }

protected:
  TraceStream(const string& trace_dir, uint32_t initial_time)
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
  uint32_t tick_time() { return ++global_time; }

  // Directory into which we're saving the trace files.
  string trace_dir;
  // Arbitrary notion of trace time, ticked on the recording of
  // each event (trace frame).
  uint32_t global_time;
};

class TraceOfstream : public TraceStream {
public:
  typedef std::shared_ptr<TraceOfstream> shr_ptr;

  /**
   * Write relevant data to the trace.
   *
   * NB: recording a trace frame has the side effect of ticking
   * the global time.
   */
  friend TraceOfstream& operator<<(TraceOfstream& tif, const TraceFrame& frame);
  friend TraceOfstream& operator<<(TraceOfstream& tif,
                                   const TraceMappedRegion& map);
  friend TraceOfstream& operator<<(TraceOfstream& tif,
                                   const struct args_env& ae);
  friend TraceOfstream& operator<<(TraceOfstream& tif,
                                   const struct raw_data& d);

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
   * Create and return a trace that will record the initial exe
   * image |exe_path|.  The trace name is determined by the
   * global rr args and environment.
   */
  static shr_ptr create(const string& exe_path);

private:
  TraceOfstream(const string& trace_dir)
      : TraceStream(trace_dir,
                    // Somewhat arbitrarily start the
                    // global time from 1.
                    1),
        events(events_path(), 1024 * 1024, 1),
        data(data_path(), 8 * 1024 * 1024, 3),
        data_header(data_header_path(), 1024 * 1024, 1),
        mmaps(mmaps_path(), 64 * 1024, 1) {}

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

class TraceIfstream : public TraceStream {
  friend struct AutoRestoreState;

public:
  typedef std::shared_ptr<TraceIfstream> shr_ptr;

  /**
   * Read relevant data from the trace.
   *
   * NB: reading a trace frame has the side effect of ticking
   * the global time to match the time recorded in the trace
   * frame.
   */
  friend TraceIfstream& operator>>(TraceIfstream& tif, TraceFrame& frame);
  friend TraceIfstream& operator>>(TraceIfstream& tif,
                                   TraceMappedRegion& map);
  friend TraceIfstream& operator>>(TraceIfstream& tif, struct args_env& ae);
  friend TraceIfstream& operator>>(TraceIfstream& tif, struct raw_data& d);

  bool read_raw_data_for_frame(const TraceFrame& frame, struct raw_data& d);

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
   * Return a copy of this stream that has exactly the same
   * state as this, but for which mutations of the returned
   * clone won't affect the state of this (and vice versa).
   */
  shr_ptr clone();

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

  /**
   * Open and return the trace specified by the command line
   * spec |argc| / |argv|.  These are just the portion of the
   * args that specify the trace, not the entire command line.
   */
  static shr_ptr open(int argc, char** argv);

  uint64_t uncompressed_bytes() const;
  uint64_t compressed_bytes() const;

private:
  TraceIfstream(const string& trace_dir)
      : TraceStream(trace_dir,
                    // Initialize the global time at 0, so
                    // that when we tick it when reading
                    // the first trace, it matches the
                    // initial global time at recording, 1.
                    0),
        events(events_path()),
        data(data_path()),
        data_header(data_header_path()),
        mmaps(mmaps_path()) {}

  TraceIfstream(const TraceIfstream& other)
      : TraceStream(other.dir(), other.time()),
        events(other.events),
        data(other.data),
        data_header(other.data_header),
        mmaps(other.mmaps) {}

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
