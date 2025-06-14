/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include <dirent.h>
#include <limits.h>
#include <linux/fs.h>
#include <linux/fiemap.h>
#include <pthread.h>
#include <string.h>
#include <sys/statvfs.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <filesystem>
#include <limits>
#include <map>
#include <set>

#include "Command.h"
#include "Flags.h"
#include "GdbServer.h"
#include "ReplaySession.h"
#include "ScopedFd.h"
#include "TraceStream.h"
#include "kernel_metadata.h"
#include "log.h"
#include "main.h"

#include "../third-party/blake2/blake2.h"

using namespace std;

namespace rr {

/**
 * Pack the trace directory to eliminate duplicate files and to include all
 * files needed for transportation.
 *
 * We try VERY HARD to avoid losing data if a PackCommand is interrupted.
 */
class PackCommand : public Command {
public:
  virtual int run(vector<string>& args) override;

protected:
  PackCommand(const char* name, const char* help) : Command(name, help) {}

  static PackCommand singleton;
};

PackCommand PackCommand::singleton(
    "pack",
    " rr pack [OPTION]... [<trace-dirs>...]\n"
    "  --symlink                  Create symlinks to all mmapped files\n"
    "                             instead of copying them.\n"
    "  --pack-dir=<path>          Specify a directory in which to pack common files.\n"
    "                             This helps conserve space when packing multiple traces\n"
    "                             with common files. Both the trace dir and pack dir\n"
    "                             (at the same relative path) are required for replay\n"
    "\n"
    "Eliminates duplicate files in the trace directory, and copies files into\n"
    "the trace directory as necessary to ensure that all needed files are in\n"
    "the trace directory and none of them are links to files outside the\n"
    "trace directory. This makes the trace directory independent of changes\n"
    "to other files and ready to be transported elsewhere (e.g. by packaging\n"
    "it into a ZIP or tar archive).\n"
    "Be careful sharing traces with others; they may contain sensitive information.\n");

struct PackFlags {
  /* If true, insert symlinks into the trace dir which point to the original
   * files, rather than copying the files themselves */
  bool symlink;
  std::string pack_dir;

  PackFlags()
      : symlink(false) {}
};

struct FileHash {
  uint8_t bytes[32];
};

bool operator<(const FileHash& h1, const FileHash& h2) {
  return memcmp(h1.bytes, h2.bytes, sizeof(h1)) < 0;
}

// Allocate a fresh FileHash different from every other
// FileHash. Not thread-safe!
static FileHash allocate_unique_file_hash() {
  static uint32_t hash = 0;
  FileHash result;
  memcpy(&result.bytes[0], &hash, sizeof(hash));
  ++hash;
  memset(&result.bytes[4], 0, sizeof(result.bytes) - sizeof(hash));
  return result;
}

struct FsExtentsHash {
  uint8_t bytes[32];
};

bool operator<(const FsExtentsHash& h1, const FsExtentsHash& h2) {
  return memcmp(h1.bytes, h2.bytes, sizeof(h1)) < 0;
}

struct PackDir {
  string dir;
  map<FileHash, string> mapped_files;
  PackDir(string dir) : dir(dir) {}
};

static bool name_comparator(const TraceReader::MappedData& d1,
                            const TraceReader::MappedData d2) {
  return d1.file_name < d2.file_name;
}

static bool names_equal(const TraceReader::MappedData& d1,
                        const TraceReader::MappedData d2) {
  return d1.file_name == d2.file_name;
}

static bool decreasing_size_comparator(const TraceReader::MappedData* d1,
                                       const TraceReader::MappedData* d2) {
  return d1->file_size_bytes > d2->file_size_bytes;
}

static bool is_hardlink(const string& file_name) {
  const char* name = file_name.c_str();
  const char* right_slash = strrchr(name, '/');
  return right_slash && strncmp(right_slash + 1, "mmap_hardlink_", 14) == 0;
}

static void* process_files_thread(void* p) {
  // Don't use log.h macros here since they're not necessarily thread-safe
  auto data = static_cast<vector<pair<const std::string*, FileHash>>*>(p);
  for (auto& pair : *data) {
    const char* name = pair.first->c_str();
    ScopedFd fd(name, O_RDONLY);
    if (!fd.is_open()) {
      fprintf(stderr, "Failed to open %s\n", name);
      exit(1);
    }
    blake2b_state b2_state;
    if (blake2b_init(&b2_state, sizeof(pair.second.bytes))) {
      fprintf(stderr, "blake2b_init failed");
      exit(1);
    }
    while (true) {
      char buf[1024 * 1024];
      ssize_t r = read(fd, buf, sizeof(buf));
      if (r < 0) {
        fprintf(stderr, "Failed reading from %s\n", name);
        exit(1);
      }
      if (r == 0) {
        break;
      }
      if (blake2b_update(&b2_state, buf, r)) {
        fprintf(stderr, "blake2b_update failed");
        exit(1);
      }
    }
    if (blake2b_final(&b2_state, pair.second.bytes,
                      sizeof(pair.second.bytes))) {
      fprintf(stderr, "blake2b_final failed");
      exit(1);
    }
  }
  return nullptr;
}

// Return a size-sorted list of all mmapped files found in the trace
static vector<TraceReader::MappedData> gather_files(const string& trace_dir) {
  TraceReader trace(trace_dir);
  vector<TraceReader::MappedData> files;
  while (true) {
    TraceReader::MappedData data;
    bool found;
    trace.read_mapped_region(&data, &found, TraceReader::VALIDATE,
                             TraceReader::ANY_TIME);
    if (!found) {
      break;
    }
    if (data.source == TraceReader::SOURCE_FILE) {
      files.push_back(data);
    }
  }

  // Eliminate duplicates
  stable_sort(files.begin(), files.end(), name_comparator);
  auto last = unique(files.begin(), files.end(), names_equal);
  files.erase(last, files.end());

  return files;
}

// Returns true if FS_IOC_FIEMAP was supported and no extents are
// UNKNOWN, storing a BLAKE2b hash of the extents metadata, file
// size and filesystem ID in `result`. Otherwise returns false and
// `result` is not initialized. `size` is always initialized.
// If two files have the same FsExtentsHash then they have the same extents
// and therefore the same contents.
// If FS_IOC_FIEMAP is supported and the extents are known then this
// deduplicates reflinked, hardlinked and symlinked files.
static bool get_file_extents_hash(const string& file_name, FsExtentsHash* result,
                                  uint64_t* size) {
  const char* name = file_name.c_str();
  ScopedFd fd(name, O_RDONLY);
  if (!fd.is_open()) {
    fprintf(stderr, "Failed to open %s\n", name);
    exit(1);
  }
  off_t seek_end = lseek(fd, 0, SEEK_END);
  if (seek_end < 0) {
    fprintf(stderr, "Failed to SEEK_END %s\n", name);
    exit(1);
  }
  *size = seek_end;

  blake2b_state b2_state;
  if (blake2b_init(&b2_state, sizeof(result->bytes))) {
    fprintf(stderr, "blake2b_init failed\n");
    exit(1);
  }
  uint64_t offset = 0;
  bool saw_last = false;
  do {
    union {
      struct fiemap request;
      char bytes[16384];
    } buffer;
    memset(&buffer.request, 0, sizeof(buffer.request));
    buffer.request.fm_start = offset;
    buffer.request.fm_length = FIEMAP_MAX_OFFSET;
    buffer.request.fm_extent_count = ((char*)&buffer.bytes[sizeof(buffer.bytes)] -
      (char*)&buffer.request.fm_extents[0])/sizeof(buffer.request.fm_extents[0]);
    int ret = ioctl(fd, FS_IOC_FIEMAP, &buffer.request);
    if (ret < 0) {
      if (errno == ENOTTY || errno == EOPNOTSUPP) {
        return false;
      }
      fprintf(stderr, "FIEMAP ioctl failed\n");
      exit(1);
    }
    if (!buffer.request.fm_mapped_extents) {
      break;
    }
    for (size_t i = 0; i < buffer.request.fm_mapped_extents; ++i) {
      const struct fiemap_extent& extent = buffer.request.fm_extents[i];
      // Be super paranoid here. In btrfs at least, we see file extents where
      // fe_physical is 0 and FIEMAP_EXTENT_DATA_INLINE|FIEMAP_EXTENT_NOT_ALIGNED
      // are set; these are not real extents and the file contents are different
      // even though the extent records are the same.
      if ((extent.fe_flags & (FIEMAP_EXTENT_UNKNOWN | FIEMAP_EXTENT_DATA_INLINE |
                              FIEMAP_EXTENT_DATA_TAIL | FIEMAP_EXTENT_NOT_ALIGNED))
          || !extent.fe_physical) {
        return false;
      }
      // It's not clear if file holes appear in the extents list or not.
      // To be on the safe side, we hash the logical offsets so any holes
      // will change the hash.
      struct {
        uint64_t fe_logical;
        uint64_t fe_physical;
        uint64_t fe_length;
        uint32_t fe_flags;
        uint32_t padding;
      } buf = {
        extent.fe_logical,
        extent.fe_physical,
        extent.fe_length,
        extent.fe_flags,
        0
      };
      if (blake2b_update(&b2_state, &buf, sizeof(buf))) {
        fprintf(stderr, "blake2b_update failed\n");
        exit(1);
      }
      if (extent.fe_flags & FIEMAP_EXTENT_LAST) {
        saw_last = true;
        break;
      }
      offset = extent.fe_logical + extent.fe_length;
    }
  } while (!saw_last);

  struct statvfs vfs_buf;
  int ret = fstatvfs(fd, &vfs_buf);
  if (ret < 0) {
    fprintf(stderr, "fstatvfs failed\n");
    exit(1);
  }
  struct {
    uint64_t size;
    uint64_t fsid;
  } buf = { *size, vfs_buf.f_fsid };
  // Make sure the file size is hashed just in case it doesn't
  // show up in the extents. We also need to hash the filesystem
  // ID because the physical extents are local to the filesystem.
  if (blake2b_update(&b2_state, &buf, sizeof(buf))) {
    fprintf(stderr, "blake2b_update failed\n");
    exit(1);
  }
  if (blake2b_final(&b2_state, result->bytes, sizeof(result->bytes))) {
    fprintf(stderr, "blake2b_final failed\n");
    exit(1);
  }
  return true;
}

// Makes a list of all mmapped files and computes their BLAKE2b hashes.
// BLAKE2b was chosen because it's fast and cryptographically strong (we don't
// compare the actual file contents, we're relying on hash collision avoidance).
// Files with the same FileHash have the same contents.
// The keys of the returned map are the full file names of the mapped files.
static map<string, FileHash> gather_file_info(const string& trace_dir) {
  vector<TraceReader::MappedData> files = gather_files(trace_dir);
  int online_cpus = sysconf(_SC_NPROCESSORS_ONLN);
  if (online_cpus < 1) {
    FATAL() << "sysconf(_SC_NPROCESSORS_ONLN) failed";
  }
  int use_cpus = min(20, online_cpus);
  use_cpus = min((int)files.size(), use_cpus);

  // List of files indexed by their extents hash. All files
  // with the same FsExtentsHash have the same contents.
  map<FsExtentsHash, vector<const TraceReader::MappedData*>> extents_to_file;
  // All files for which we failed to get extents. We know nothing
  // about their contents.
  vector<const TraceReader::MappedData*> files_with_no_extents;
  for (const auto& file : files) {
    FsExtentsHash extents_hash;
    uint64_t size;
    if (get_file_extents_hash(file.file_name, &extents_hash, &size)) {
      extents_to_file[extents_hash].push_back(&file);
    } else {
      files_with_no_extents.push_back(&file);
    }
    if (size != file.file_size_bytes) {
      fprintf(stderr, "File size mismatch for %s\n", file.file_name.c_str());
      exit(1);
    }
  }

  // Make a list of files with possibly unique contents (i.e. excluding
  // duplicates with the same FsExtentsHash).
  vector<const TraceReader::MappedData*> files_to_hash = files_with_no_extents;
  for (const auto& entry : extents_to_file) {
    files_to_hash.push_back(entry.second[0]);
  }
  // We'll assign files to threads in round-robin order, ordered by decreasing size.
  stable_sort(files_to_hash.begin(), files_to_hash.end(),
              decreasing_size_comparator);

  map<uint64_t, int32_t> file_size_to_file_count;
  for (auto file : files_to_hash) {
    ++file_size_to_file_count[file->file_size_bytes];
  }

  map<string, FileHash> result;
  vector<vector<pair<const std::string*, FileHash>>> thread_files;
  thread_files.resize(use_cpus);
  int num_files_to_hash = 0;
  for (auto file : files_to_hash) {
    if (file_size_to_file_count[file->file_size_bytes] == 1) {
      // There is only one file with this size, so it can't be a duplicate
      // of any other files in `files_to_hash` and there is no need to hash
      // its contents. We'll just make up a fake, unique hash value for it.
      result[file->file_name] = allocate_unique_file_hash();
      continue;
    }
    thread_files[num_files_to_hash % use_cpus].push_back(
        make_pair(&file->file_name, FileHash()));
    ++num_files_to_hash;
  }

  // Use multiple threads to actually hash the files we need to hash.
  vector<pthread_t> threads;
  for (size_t i = 0; i < thread_files.size(); ++i) {
    pthread_t thread;
    pthread_create(&thread, nullptr, process_files_thread, &thread_files[i]);
    threads.push_back(thread);
  }
  for (pthread_t t : threads) {
    pthread_join(t, nullptr);
  }
  for (auto& f : thread_files) {
    for (auto& ff : f) {
      result[*ff.first] = ff.second;
    }
  }

  // Populate results for files we skipped because they had duplicate
  // FsExtentsHashes.
  for (const auto& entry : extents_to_file) {
    for (size_t i = 1; i < entry.second.size(); ++i) {
      // Taking a reference into `result` while we potentially
      // rehash it could be bad.
      FileHash h = result[entry.second[0]->file_name];
      result[entry.second[i]->file_name] = h;
    }
  }

  return result;
}

static bool is_in_trace_dir(const string& file_name, const string& trace_dir) {
  return file_name.find(trace_dir) == 0;
}

static const char* last_filename_component(const string& file_name) {
  const char* last_slash = strrchr(file_name.c_str(), '/');
  const char* last_component = last_slash ? last_slash + 1 : file_name.c_str();
  if (strncmp(last_component, "mmap_hardlink_", 14) == 0) {
    last_component += 14;
    while (*last_component && *last_component != '_') {
      ++last_component;
    }
    if (*last_component == '_') {
      ++last_component;
    }
  }
  return last_component;
}

static string copy_into_trace(const string& file_name, const string& trace_dir,
                              int* name_index) {
  // We don't bother trying to do a reflink-copy here because if that was going
  // to succeed, rr would probably already have used it during recording.
  string new_name;
  ScopedFd out_fd;
  const char* last_component = last_filename_component(file_name);
  while (true) {
    char new_name_buf[PATH_MAX];
    snprintf(new_name_buf, sizeof(new_name_buf) - 1, "mmap_pack_%d_%s",
             *name_index, last_component);
    new_name_buf[sizeof(new_name_buf) - 1] = 0;
    new_name = trace_dir + "/" + new_name_buf;
    ++*name_index;
    out_fd = ScopedFd(new_name.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0700);
    if (!out_fd.is_open()) {
      if (errno == EEXIST) {
        continue;
      }
      FATAL() << "Couldn't create " << new_name;
    }
    break;
  }

  ScopedFd in_fd(file_name.c_str(), O_RDONLY);
  if (!in_fd.is_open()) {
    FATAL() << "Couldn't open " << file_name;
  }

  while (true) {
    char buf[1024 * 1024];
    ssize_t r = read(in_fd, buf, sizeof(buf));
    if (r < 0) {
      FATAL() << "Can't read from " << file_name;
    }
    if (r == 0) {
      break;
    }
    ssize_t written = 0;
    while (written < r) {
      ssize_t w = write(out_fd, buf + written, r - written);
      if (w <= 0) {
        FATAL() << "Can't write to " << new_name;
      }
      written += w;
    }
  }

  // Try to avoid dataloss
  if (fsync(out_fd) < 0) {
    FATAL() << "Can't write to " << new_name;
  }

  return new_name;
}

// Generates a symlink inside the trace directory, pointing to the provided
// file name.
static string symlink_into_trace(const string& file_name,
                                 const string& trace_dir, int* name_index) {
  string new_name;
  ScopedFd out_fd;
  const char* last_component = last_filename_component(file_name);
  while (true) {
    char new_name_buf[PATH_MAX];
    snprintf(new_name_buf, sizeof(new_name_buf) - 1, "mmap_symlink_%d_%s",
             *name_index, last_component);
    new_name_buf[sizeof(new_name_buf) - 1] = 0;
    new_name = trace_dir + "/" + new_name_buf;
    ++*name_index;
    int ret = symlink(file_name.c_str(), new_name.c_str());
    if (ret < 0) {
      if (errno == EEXIST) {
        continue;
      }
      FATAL() << "Couldn't create symlink `" << new_name << "' to `"
              << file_name << "'.";
    }
    break;
  }
  return new_name;
}

// Insert symlinks into the trace directory, one for each mmapped file found in
// the trace. Returns a mapping of absolute original file paths and the new
// relative paths to the symlinks which are to be used in their place. Files
// that already exist in the trace directory (including hardlinks) are left
// in place and not symlinked.
static map<string, string> compute_canonical_symlink_map(
    const string& trace_dir) {
  map<string, string> symlink_map;
  int name_index = 0;

  // Get all mmapped files from trace
  vector<TraceReader::MappedData> files = gather_files(trace_dir);

  for (auto& p : files) {
    string name = p.file_name;
    // If file is not in trace dir, create a symlink to it
    if (!is_in_trace_dir(p.file_name, trace_dir)) {
      name = symlink_into_trace(p.file_name, trace_dir, &name_index);
    }
    // Update the file map with the relative path of the target file
    symlink_map[p.file_name] = string(strrchr(name.c_str(), '/') + 1);
  }

  return symlink_map;
}

/**
 * This computes a map giving, for each file referenced in the trace, the name
 * of a trace file to use instead. This copies files into the
 * trace directory if they're not in the tracedir already, or if they're
 * hardlinks to files outside the trace directory. All of the copied files
 * will have names starting with "mmap_pack_". For files in the trace directory
 * that have the same hash, we select just one of the files as the destination
 * for all files with that hash.
 */
static map<string, string> compute_canonical_mmapped_files(
    const string& trace_dir,
    PackDir &pack_dir) {
  map<string, FileHash> file_info = gather_file_info(trace_dir);

  map<FileHash, string> hash_to_name;
  for (auto& p : file_info) {
    const auto& existing = hash_to_name.find(p.second);
    if (existing != hash_to_name.end()) {
      if (!is_hardlink(existing->second) &&
          is_in_trace_dir(existing->second, trace_dir)) {
        continue;
      }
    }
    hash_to_name[p.second] = p.first;
  }

  int name_index = 0;
  for (auto& p : hash_to_name) {
    // Check if this in our common pack directory
    auto it = pack_dir.mapped_files.find(p.first);
    if (it != pack_dir.mapped_files.end()) {
      LOG(debug) << "Found in common pack dir";
      p.second = symlink_into_trace(filesystem::relative(it->second, trace_dir), trace_dir, &name_index);
      continue;
    }

    // Copy hardlinked files into the trace to avoid the possibility of someone
    // overwriting the original file.
    if (is_hardlink(p.second) || !is_in_trace_dir(p.second, trace_dir)) {
      if (pack_dir.dir != "") {
        // If a pack dir is specified, first copy into pack dir, then symlink into trace.
        auto path = pack_dir.mapped_files[p.first] = copy_into_trace(p.second, pack_dir.dir, &name_index);
        p.second = symlink_into_trace(filesystem::relative(path, trace_dir), trace_dir, &name_index);
      } else {
        p.second = copy_into_trace(p.second, trace_dir, &name_index);
      }
    }
  }

  map<string, string> file_map;
  for (auto& p : file_info) {
    string name = hash_to_name[p.second];
    if (!is_in_trace_dir(name, trace_dir)) {
      FATAL() << "Internal error; file is not in trace dir";
    }
    // Replace absolute paths with trace-relative file names
    file_map[p.first] = string(strrchr(name.c_str(), '/') + 1);
  }

  return file_map;
}

// Write out a new 'mmaps' file with the new file names and atomically
// replace the existing 'mmaps' file with it.
static void rewrite_mmaps(const map<string, string>& file_map,
                          const string& trace_dir) {
  string path = trace_dir + "/pack_mmaps";
  CompressedWriter writer(path, TraceStream::mmaps_block_size(), 1);

  TraceReader trace(trace_dir);
  vector<TraceReader::MappedData> files;
  while (true) {
    TraceReader::MappedData data;
    bool found;
    vector<TraceRemoteFd> extra_fds;
    bool skip_monitoring_mapped_fd;
    KernelMapping km = trace.read_mapped_region(
        &data, &found, TraceReader::VALIDATE, TraceReader::ANY_TIME,
        &extra_fds, &skip_monitoring_mapped_fd);
    if (!found) {
      break;
    }
    if (data.source == TraceReader::SOURCE_FILE) {
      auto m = file_map.find(data.file_name);
      if (m == file_map.end()) {
        FATAL() << "Internal error, didn't assign file " << data.file_name;
      }
      data.file_name = m->second;
    }
    TraceWriter::write_mapped_region_to_alternative_stream(
        writer, data, km, extra_fds, skip_monitoring_mapped_fd);
  }

  // Try not to lose data!
  writer.close(CompressedWriter::SYNC);
  if (!writer.good()) {
    FATAL() << "Error writing " << path;
  }

  // OK, now the atomic switchover to the new maps file.
  // BEFORE this point, we haven't altered any of the original trace files.
  // A crash might leave some "mmap_pack_" files around but that's OK. A retried
  // "rr pack" that runs to completion will clean them all up.
  // AFTER this point, we have altered the mmaps file and the trace remains
  // valid.
  string mmaps_path = trace_dir + "/mmaps";
  if (rename(path.c_str(), mmaps_path.c_str()) < 0) {
    FATAL() << "Error renaming " << path << " to " << mmaps_path;
  }
}

// Delete any "mmap_" files that aren't destination files in our file_map.
static void delete_unnecessary_files(const map<string, string>& file_map,
                                     const string& trace_dir) {
  set<string> retain;
  for (auto& p : file_map) {
    retain.insert(p.second);
  }

  DIR* dir = opendir(trace_dir.c_str());
  if (!dir) {
    FATAL() << "Can't open directory " << trace_dir;
  }
  struct dirent* d;
  errno = 0;
  vector<string> names;
  while ((d = readdir(dir)) != nullptr) {
    if (strncmp(d->d_name, "mmap_", 5) == 0 &&
        retain.count(string(d->d_name)) == 0) {
      names.push_back(string(d->d_name));
    }
  }
  if (errno) {
    FATAL() << "Can't read directory " << trace_dir;
  }
  closedir(dir);

  for (auto& n : names) {
    string name = trace_dir + "/" + n;
    if (unlink(name.c_str()) < 0) {
      FATAL() << "Can't delete file " << name;
    }
  }
}

static int pack(const vector<string>& trace_dirs, const PackFlags& flags) {
  for (const string &trace_dir : trace_dirs) {
    string dir;
    {
      // validate trace and produce default trace directory if trace_dir is empty
      TraceReader reader(trace_dir);
      dir = reader.dir();
    }

    PackDir pack_dir(flags.pack_dir);
    char buf[PATH_MAX];
    char* ret = realpath(dir.c_str(), buf);
    if (!ret) {
      FATAL() << "realpath failed on " << dir;
    }
    string abspath(buf);

    if (flags.symlink) {
      map<string, string> canonical_symlink_map =
          compute_canonical_symlink_map(abspath);
      rewrite_mmaps(canonical_symlink_map, abspath);
      delete_unnecessary_files(canonical_symlink_map, abspath);
    } else {
      map<string, string> canonical_mmapped_files =
          compute_canonical_mmapped_files(abspath, pack_dir);
      rewrite_mmaps(canonical_mmapped_files, abspath);
      delete_unnecessary_files(canonical_mmapped_files, abspath);
    }

    if (!probably_not_interactive(STDOUT_FILENO)) {
      printf("rr: Packed trace directory `%s'.\n", dir.c_str());
    }
  }

  return 0;
}

static bool parse_pack_arg(vector<string>& args, PackFlags& flags) {
  static const OptionSpec options[] = {
    { 0, "symlink", NO_PARAMETER },
    { 1, "pack-dir", HAS_PARAMETER },
  };
  ParsedOption opt;
  auto args_copy = args;
  if (!Command::parse_option(args_copy, options, &opt)) {
    return false;
  }

  switch (opt.short_name) {
    case 0:
      flags.symlink = true;
      break;
    case 1:
      flags.pack_dir = opt.value;
      break;
    default:
      DEBUG_ASSERT(0 && "Unknown pack option");
  }

  args = args_copy;
  return true;
}

int PackCommand::run(vector<string>& args) {
  PackFlags flags;

  while (parse_pack_arg(args, flags)) {
  }

  vector<string> trace_dirs;
  while (!args.empty()) {
    string trace_dir;
    if (!parse_optional_trace_dir(args, &trace_dir)) {
      print_help(stderr);
      return 1;
    }
    trace_dirs.push_back(trace_dir);
  }

  // If no trace dirs were supplied, default to packing "", i.e. the latest trace.
  if (trace_dirs.empty()) {
    trace_dirs.push_back("");
  }

  return pack(trace_dirs, flags);
}

} // namespace rr
