/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_TRACE_H_
#define RR_TRACE_H_

#include <unistd.h>

#include <memory>
#include <set>
#include <string>
#include <vector>

#include "CompressedReader.h"
#include "CompressedWriter.h"
#include "Event.h"
#include "TaskishUid.h"
#include "TraceFrame.h"
#include "TraceTaskEvent.h"
#include "remote_ptr.h"

namespace rr {

class KernelMapping;
class Task;

/**
 * TraceStream stores all the data common to both recording and
 * replay.  TraceWriter deals with recording-specific logic, and
 * TraceReader handles replay-specific details.
 *
 * These classes are all in the same .h/.cc file to keep trace reading and
 * writing code together for easier coordination.
 */
class TraceStream {
protected:
  typedef std::string string;

public:
  /**
   * Update |substreams| and TRACE_VERSION when you update this list.
   */
  enum Substream {
    SUBSTREAM_FIRST,
    // Substream that stores events (trace frames).
    EVENTS = SUBSTREAM_FIRST,
    // Substreams that store raw data saved from tracees (|RAW_DATA|), and
    // metadata about the stored data (|RAW_DATA_HEADER|).
    RAW_DATA_HEADER,
    RAW_DATA,
    // Substream that stores metadata about files mmap'd during
    // recording.
    MMAPS,
    // Substream that stores task creation and exec events
    TASKS,
    // Substream that stores arbitrary per-event records
    GENERIC,
    SUBSTREAM_COUNT
  };

  /** Return the directory storing this trace's files. */
  const string& dir() const { return trace_dir; }

  int bound_to_cpu() const { return bind_to_cpu; }

  /**
   * Return the current "global time" (event count) for this
   * trace.
   */
  TraceFrame::Time time() const { return global_time; }

  std::string file_data_clone_file_name(const TaskUid& tuid);

protected:
  TraceStream(const string& trace_dir, TraceFrame::Time initial_time)
      : trace_dir(trace_dir), global_time(initial_time) {}

  /**
   * Return the path of the file for the given substream.
   */
  string path(Substream s);

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
  // CPU core# that the tracees are bound to
  int32_t bind_to_cpu;

  // Arbitrary notion of trace time, ticked on the recording of
  // each event (trace frame).
  TraceFrame::Time global_time;
};

class TraceWriter : public TraceStream {
public:
  bool supports_file_data_cloning() { return supports_file_data_cloning_; }

  /**
   * Write trace frame to the trace.
   *
   * Recording a trace frame has the side effect of ticking
   * the global time.
   */
  void write_frame(const TraceFrame& frame);

  enum RecordInTrace { DONT_RECORD_IN_TRACE, RECORD_IN_TRACE };
  enum MappingOrigin {
    SYSCALL_MAPPING,
    EXEC_MAPPING,
    PATCH_MAPPING,
    RR_BUFFER_MAPPING
  };
  /**
   * Write mapped-region record to the trace.
   * If this returns RECORD_IN_TRACE, then the data for the map should be
   * recorded in the trace raw-data.
   */
  RecordInTrace write_mapped_region(Task* t, const KernelMapping& map,
                                    const struct stat& stat,
                                    MappingOrigin origin = SYSCALL_MAPPING);

  /**
   * Write a raw-data record to the trace.
   * 'addr' is the address in the tracee where the data came from/will be
   * restored to.
   */
  void write_raw(const void* data, size_t len, remote_ptr<void> addr);

  /**
   * Write a task event (clone or exec record) to the trace.
   */
  void write_task_event(const TraceTaskEvent& event);

  /**
   * Write a generic data record to the trace.
   */
  void write_generic(const void* data, size_t len);

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
   * Create a trace where the tracess are bound to cpu |bind_to_cpu|. This
   * data is recorded in the trace.
   * The trace name is determined by |file_name| and _RR_TRACE_DIR (if set).
   */
  TraceWriter(const std::string& file_name, int bind_to_cpu);

  /**
   * We got far enough into recording that we should set this as the latest
   * trace.
   */
  void make_latest_trace();

private:
  std::string try_hardlink_file(const std::string& file_name);
  bool try_clone_file(const std::string& file_name, std::string* new_name);

  CompressedWriter& writer(Substream s) { return *writers[s]; }
  const CompressedWriter& writer(Substream s) const { return *writers[s]; }

  std::unique_ptr<CompressedWriter> writers[SUBSTREAM_COUNT];
  /**
   * Files that have already been mapped without being copied to the trace,
   * i.e. that we have already assumed to be immutable.
   */
  std::set<std::pair<dev_t, ino_t> > files_assumed_immutable;
  uint32_t mmap_count;
  bool supports_file_data_cloning_;
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
  TraceFrame read_frame();

  enum MappedDataSource { SOURCE_TRACE, SOURCE_FILE, SOURCE_ZERO };
  /**
   * Where to obtain data for the mapped region.
   */
  struct MappedData {
    MappedDataSource source;
    /** Name of file to map the data from. */
    string file_name;
    /** Data offset within |file_name|. */
    uint64_t data_offset_bytes;
    /** Original size of mapped file. */
    uint64_t file_size_bytes;
  };
  /**
   * Read the next mapped region descriptor and return it.
   * Also returns where to get the mapped data in |*data|, if it's non-null.
   * If |found| is non-null, set |*found| to indicate whether a descriptor
   * was found for the current event.
   */
  enum ValidateSourceFile { VALIDATE, DONT_VALIDATE };
  enum TimeConstraint { CURRENT_TIME_ONLY, ANY_TIME };
  KernelMapping read_mapped_region(
      MappedData* data = nullptr, bool* found = nullptr,
      ValidateSourceFile validate = VALIDATE,
      TimeConstraint time_constraint = CURRENT_TIME_ONLY);

  /**
   * Read a task event (clone or exec record) from the trace.
   * Returns a record of type NONE at the end of the trace.
   */
  TraceTaskEvent read_task_event();

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

  void read_generic(std::vector<uint8_t>& out);
  bool read_generic_for_frame(const TraceFrame& frame,
                              std::vector<uint8_t>& out);

  /**
   * Return true iff all trace files are "good".
   * for more details.
   */
  bool good() const;

  /**
   * Return true if we're at the end of the trace file.
   */
  bool at_end() const { return reader(EVENTS).at_end(); }

  /**
   * Return the next trace frame, without mutating any stream
   * state.
   */
  TraceFrame peek_frame();

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
  TraceReader(const string& dir);

  /**
   * Create a copy of this stream that has exactly the same
   * state as 'other', but for which mutations of this
   * clone won't affect the state of 'other' (and vice versa).
   */
  TraceReader(const TraceReader& other);

private:
  CompressedReader& reader(Substream s) { return *readers[s]; }
  const CompressedReader& reader(Substream s) const { return *readers[s]; }

  std::unique_ptr<CompressedReader> readers[SUBSTREAM_COUNT];
};

} // namespace rr

#endif /* RR_TRACE_H_ */
