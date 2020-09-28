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
struct TraceUuid;

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
    size_t data_offset_bytes;
    /** Original size of mapped file. */
    size_t file_size_bytes;
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

struct TraceRemoteFd {
  pid_t tid;
  int fd;
};

/**
 * Trace writing takes the trace directory through a defined set of states.
 * These states can be usefully observed by external programs.
 *
 * -- Initially the trace directory does not exist.
 * -- The trace directory is created. It is empty.
 * -- A file `incomplete` is created in the trace directory. It is empty.
 * -- rr takes an exclusive flock() lock on `incomplete`.
 * -- rr writes data to `incomplete` so it is no longer empty. (At this
 * point the data is undefined.) rr may write to the file at any
 * time during recording.
 * -- At the end of trace recording, rr renames `incomplete` to `version`.
 * At this point the trace is complete and ready to replay.
 * -- rr releases its flock() lock on `version`.
 *
 * Thus:
 * -- If the trace directory contains the file `version` the trace is valid
 * and ready for replay.
 * -- If the trace directory contains the file `incomplete`, and there is an
 * exclusive flock() lock on that file, rr is still recording (or something
 * is messing with us).
 * -- If the trace directory contains the file `incomplete`, that file
 * does not have an exclusive `flock()` lock on it, and the file is non-empty,
 * rr must have died before the recording was complete.
 * -- If the trace directory contains the file `incomplete`, that file
 * does not have an exclusive `flock()` lock on it, and the file is empty,
 * rr has just started recording (or perhaps died during startup).
 * -- If the trace directory does not contain the file `incomplete`,
 * rr has just started recording (or perhaps died during startup) (or perhaps
 * that isn't a trace directory at all).
 */
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
                                    const std::string &file_name,
                                    const std::vector<TraceRemoteFd>& extra_fds,
                                    MappingOrigin origin = SYSCALL_MAPPING,
                                    bool skip_monitoring_mapped_fd = false);

  static void write_mapped_region_to_alternative_stream(
      CompressedWriter& mmaps, const MappedData& data, const KernelMapping& km,
      const std::vector<TraceRemoteFd>& extra_fds, bool skip_monitoring_mapped_fd);

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

  /**
   * Create a trace where the tracess are bound to cpu |bind_to_cpu|. This
   * data is recorded in the trace. If |bind_to_cpu| is -1 then the tracees
   * were not bound.
   * The trace name is determined by |file_name| and _RR_TRACE_DIR (if set)
   * or by setting -o=<OUTPUT_TRACE_DIR>.
   */
  TraceWriter(const std::string& file_name,
              const string& output_trace_dir, TicksSemantics ticks_semantics);

  /**
   * Called after the calling thread is actually bound to |bind_to_cpu|.
   */
  void setup_cpuid_records(bool has_cpuid_faulting,
                           const DisableCPUIDFeatures& disable_cpuid_features);

  void set_xsave_fip_fdp_quirk(bool value) { xsave_fip_fdp_quirk_ = value; }
  void set_fdp_exception_only_quirk(bool value) { fdp_exception_only_quirk_ = value; }
  void set_clear_fip_fdp(bool value) { clear_fip_fdp_ = value; }
  bool clear_fip_fdp() const { return clear_fip_fdp_; }

  enum CloseStatus {
    /**
     * Trace completed normally and can be replayed.
     */
    CLOSE_OK,
    /**
     * Trace completed abnormally due to rr error.
     */
    CLOSE_ERROR
  };
  /** Call close() on all the relevant trace files.
   *  Normally this will be called by the destructor. It's helpful to
   *  call this before a crash that won't call the destructor, to ensure
   *  buffered data is flushed.
   */
  void close(CloseStatus status, const TraceUuid* uuid);

  /**
   * We got far enough into recording that we should set this as the latest
   * trace.
   */
  void make_latest_trace();

  TicksSemantics ticks_semantics() const { return ticks_semantics_; }

private:
  bool try_hardlink_file(const std::string& real_file_name,
                         const std::string& access_file_name, std::string* new_name);
  bool try_clone_file(RecordTask* t, const std::string& real_file_name,
                      const std::string& access_file_name,
                      std::string* new_name);
  bool copy_file(const std::string& real_file_name,
                 const std::string& access_file_name, std::string* new_name);

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
  std::vector<CPUIDRecord> cpuid_records;
  TicksSemantics ticks_semantics_;
  // Keep the 'incomplete' (later renamed to 'version') file open until we
  // rename it, so our flock() lock stays held on it.
  ScopedFd version_fd;
  uint32_t mmap_count;
  bool has_cpuid_faulting_;
  bool xsave_fip_fdp_quirk_;
  bool fdp_exception_only_quirk_;
  bool clear_fip_fdp_;
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
      TimeConstraint time_constraint = CURRENT_TIME_ONLY,
      std::vector<TraceRemoteFd>* extra_fds = nullptr,
      bool* skip_monitoring_mapped_fd = nullptr);

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
  bool clear_fip_fdp() const { return clear_fip_fdp_; }
  // Prior to issue 2370, we did not emit mapping into the trace for the
  // preload_thread_locals mapping if it was created by a clone(2) without
  // CLONE_VM. This is true if that has been fixed.
  bool preload_thread_locals_recorded() const { return preload_thread_locals_recorded_; }
  const TraceUuid& uuid() const { return *uuid_; }

  TicksSemantics ticks_semantics() const { return ticks_semantics_; }

  double recording_time() const { return monotonic_time_; }

  // The base syscall number for rr syscalls in this trace
  int rrcall_base() const { return rrcall_base_; }

  SupportedArch arch() const { return arch_; }

  // Whether the /proc/<pid>/mem calls were explicitly recorded in this trace
  bool explicit_proc_mem() const { return explicit_proc_mem_; }

private:
  CompressedReader& reader(Substream s) { return *readers[s]; }
  const CompressedReader& reader(Substream s) const { return *readers[s]; }

  uint64_t xcr0_;
  std::unique_ptr<CompressedReader> readers[SUBSTREAM_COUNT];
  std::vector<CPUIDRecord> cpuid_records_;
  std::vector<RawDataMetadata> raw_recs;
  TicksSemantics ticks_semantics_;
  double monotonic_time_;
  std::unique_ptr<TraceUuid> uuid_;
  bool trace_uses_cpuid_faulting;
  bool preload_thread_locals_recorded_;
  bool clear_fip_fdp_;
  int rrcall_base_;
  SupportedArch arch_;
  bool explicit_proc_mem_;
};

extern std::string trace_save_dir();
extern std::string resolve_trace_name(const std::string& trace_name);

} // namespace rr

#endif /* RR_TRACE_STREAM_H_ */
