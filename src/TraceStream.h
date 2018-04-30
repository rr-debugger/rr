/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_TRACE_STREAM_H_
#define RR_TRACE_STREAM_H_

#include <unistd.h>

#include <map>
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

struct CPUIDRecord;
struct DisableCPUIDFeatures;
class KernelMapping;
class RecordTask;

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
  struct RawDataMetadata {
    remote_ptr<void> addr;
    size_t size;
    pid_t rec_tid;
  };

  /**
   * Update |substreams| and TRACE_VERSION when you update this list.
   */
  enum Substream {
    SUBSTREAM_FIRST,
    // Substream that stores events (trace frames).
    EVENTS = SUBSTREAM_FIRST,
    RAW_DATA,
    // Substream that stores metadata about files mmap'd during
    // recording.
    MMAPS,
    // Substream that stores task creation and exec events
    TASKS,
    SUBSTREAM_COUNT
  };

  /** Return the directory storing this trace's files. */
  const string& dir() const { return trace_dir; }

  int bound_to_cpu() const { return bind_to_cpu; }
  void set_bound_cpu(int bound) { bind_to_cpu = bound; }

  /**
   * Return the current "global time" (event count) for this
   * trace.
   */
  FrameTime time() const { return global_time; }

  std::string file_data_clone_file_name(const TaskUid& tuid);

  static size_t mmaps_block_size();

  /**
   * For REMAP_MAPPING maps, the memory contents are preserved so we don't
   * need a source. We use SOURCE_ZERO for that case and it's ignored.
   */
  enum MappedDataSource { SOURCE_TRACE, SOURCE_FILE, SOURCE_ZERO };
  /**
   * Where to obtain data for the mapped region.
   */
  struct MappedData {
    FrameTime time;
    MappedDataSource source;
    /** Name of file to map the data from. */
    string file_name;
    /** Data offset within |file_name|. */
    uint64_t data_offset_bytes;
    /** Original size of mapped file. */
    uint64_t file_size_bytes;
  };

protected:
  TraceStream(const string& trace_dir, FrameTime initial_time);

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
   * While the trace is being built, the version file is stored under this name.
   * When the trace is closed we rename it to the correct name. This lets us
   * detect incomplete traces.
   */
  string incomplete_version_path() const { return trace_dir + "/incomplete"; }

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
  FrameTime global_time;
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
  void write_frame(RecordTask* t, const Event& ev, const Registers* registers,
                   const ExtraRegisters* extra_registers);

  enum RecordInTrace { DONT_RECORD_IN_TRACE, RECORD_IN_TRACE };
  enum MappingOrigin {
    SYSCALL_MAPPING,
    // Just memory moved from one place to another, so no recording needed.
    REMAP_MAPPING,
    EXEC_MAPPING,
    PATCH_MAPPING,
    RR_BUFFER_MAPPING
  };
  /**
   * Write mapped-region record to the trace.
   * If this returns RECORD_IN_TRACE, then the data for the map should be
   * recorded in the trace raw-data.
   */
  RecordInTrace write_mapped_region(RecordTask* t, const KernelMapping& map,
                                    const struct stat& stat,
                                    MappingOrigin origin = SYSCALL_MAPPING);

  static void write_mapped_region_to_alternative_stream(
      CompressedWriter& mmaps, const MappedData& data, const KernelMapping& km);

  /**
   * Write a raw-data record to the trace.
   * 'addr' is the address in the tracee where the data came from/will be
   * restored to.
   */
  void write_raw(pid_t tid, const void* data, size_t len,
                 remote_ptr<void> addr);

  /**
   * Write a task event (clone or exec record) to the trace.
   */
  void write_task_event(const TraceTaskEvent& event);

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
   * data is recorded in the trace. If |bind_to_cpu| is -1 then the tracees
   * were not bound.
   * The trace name is determined by |file_name| and _RR_TRACE_DIR (if set).
   */
  TraceWriter(const std::string& file_name, int bind_to_cpu,
              bool has_cpuid_faulting,
              const DisableCPUIDFeatures& disable_cpuid_features);

  /**
   * We got far enough into recording that we should set this as the latest
   * trace.
   */
  void make_latest_trace();

private:
  bool try_hardlink_file(const std::string& file_name, std::string* new_name);
  bool try_clone_file(RecordTask* t, const std::string& file_name,
                      std::string* new_name);
  bool copy_file(const std::string& file_name, std::string* new_name);

  CompressedWriter& writer(Substream s) { return *writers[s]; }
  const CompressedWriter& writer(Substream s) const { return *writers[s]; }

  std::unique_ptr<CompressedWriter> writers[SUBSTREAM_COUNT];
  /**
   * Files that have already been mapped without being copied to the trace,
   * i.e. that we have already assumed to be immutable.
   * We store the file name under which we assumed it to be immutable, since
   * a file may be accessed through multiple names, only some of which
   * are immutable.
   */
  std::map<std::pair<dev_t, ino_t>, std::string> files_assumed_immutable;
  std::vector<RawDataMetadata> raw_recs;
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
    pid_t rec_tid;
  };

  /**
   * Read relevant data from the trace.
   *
   * NB: reading a trace frame has the side effect of ticking
   * the global time to match the time recorded in the trace
   * frame.
   */
  TraceFrame read_frame();

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
   * Sets |*time| (if non-null) to the global time of the event.
   */
  TraceTaskEvent read_task_event(FrameTime* time = nullptr);

  /**
   * Read the next raw data record for this frame and return it. Aborts if
   * there are no more raw data records for this frame.
   */
  RawData read_raw_data();

  /**
   * Reads the next raw data record for last-read frame. If there are no more
   * raw data records for this frame, return false.
   */
  bool read_raw_data_for_frame(RawData& d);

  /**
   * Like read_raw_data_for_frame, but doesn't actually read the data bytes.
   * The array is resized but the data is not filled in.
   */
  bool read_raw_data_metadata_for_frame(RawDataMetadata& d);

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

  ~TraceReader();

  const std::vector<CPUIDRecord>& cpuid_records() const {
    return cpuid_records_;
  }
  bool uses_cpuid_faulting() const { return trace_uses_cpuid_faulting; }
  uint64_t xcr0() const;

private:
  CompressedReader& reader(Substream s) { return *readers[s]; }
  const CompressedReader& reader(Substream s) const { return *readers[s]; }

  uint64_t xcr0_;
  std::unique_ptr<CompressedReader> readers[SUBSTREAM_COUNT];
  std::vector<CPUIDRecord> cpuid_records_;
  std::vector<RawDataMetadata> raw_recs;
  bool trace_uses_cpuid_faulting;
};

} // namespace rr

#endif /* RR_TRACE_STREAM_H_ */
