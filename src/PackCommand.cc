/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include <dirent.h>
#include <limits.h>
#include <pthread.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
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
    " rr pack [<trace-dir>]\n"
    "\n"
    "Eliminates duplicate files in the trace directory, and copies files into\n"
    "the trace directory as necessary to ensure that all needed files are in\n"
    "the trace directory and none of them are links to files outside the\n"
    "trace directory. This makes the trace directory independent of changes\n"
    "to other files and ready to be transported elsewhere (e.g. by packaging\n"
    "it into a ZIP or tar archive).\n");

struct FileHash {
  uint8_t bytes[32];
};

bool operator<(const FileHash& h1, const FileHash& h2) {
  return memcmp(h1.bytes, h2.bytes, sizeof(h1)) < 0;
}

struct FileInfo {
  FileHash hash;
  uint64_t size;
  bool is_hardlink;
};

static bool name_comparator(const TraceReader::MappedData& d1,
                            const TraceReader::MappedData d2) {
  return d1.file_name < d2.file_name;
}

static bool names_equal(const TraceReader::MappedData& d1,
                        const TraceReader::MappedData d2) {
  return d1.file_name == d2.file_name;
}

static bool size_comparator(const TraceReader::MappedData& d1,
                            const TraceReader::MappedData d2) {
  return d1.data_offset_bytes > d2.data_offset_bytes;
}

static void* process_files_thread(void* p) {
  // Don't use log.h macros here since they're not necessarily thread-safe
  auto data = static_cast<vector<pair<TraceReader::MappedData, FileInfo>>*>(p);
  for (auto& pair : *data) {
    const char* name = pair.first.file_name.c_str();
    const char* right_slash = strrchr(name, '/');
    pair.second.is_hardlink =
        right_slash && strncmp(right_slash + 1, "mmap_hardlink_", 14) == 0;

    ScopedFd fd(name, O_RDONLY);
    if (!fd.is_open()) {
      fprintf(stderr, "Failed to open %s\n", name);
      exit(1);
    }
    struct stat stat_buf;
    if (fstat(fd, &stat_buf) < 0) {
      fprintf(stderr, "Failed to stat %s\n", name);
      exit(1);
    }
    if (uint64_t(stat_buf.st_size) != pair.first.file_size_bytes) {
      fprintf(stderr, "File size mismatch for %s\n", name);
      exit(1);
    }
    pair.second.size = stat_buf.st_size;

    blake2b_state b2_state;
    if (blake2b_init(&b2_state, sizeof(pair.second.hash.bytes))) {
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
    if (blake2b_final(&b2_state, pair.second.hash.bytes,
                      sizeof(pair.second.hash.bytes))) {
      fprintf(stderr, "blake2b_final failed");
      exit(1);
    }
  }
  return nullptr;
}

// Collect list of all mapped files and compute their BLAKE2b hashes.
// BLAKE2b was chosen because it's fast and cryptographically strong (we don't
// compare the actual file contents, we're relying on hash collision avoidance).
static map<string, FileInfo> gather_file_info(const string& trace_dir) {
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

  // First, eliminate duplicates
  stable_sort(files.begin(), files.end(), name_comparator);
  auto last = unique(files.begin(), files.end(), names_equal);
  files.erase(last, files.end());

  // Then sort by decreasing size
  stable_sort(files.begin(), files.end(), size_comparator);
  int use_cpus = min(20, get_num_cpus());
  use_cpus = min((int)files.size(), use_cpus);

  // Assign files round-robin to threads
  vector<vector<pair<TraceReader::MappedData, FileInfo>>> thread_files;
  thread_files.resize(use_cpus);
  for (size_t i = 0; i < files.size(); ++i) {
    FileInfo info;
    thread_files[i % use_cpus].push_back(make_pair(files[i], info));
  }

  vector<pthread_t> threads;
  for (size_t i = 0; i < thread_files.size(); ++i) {
    pthread_t thread;
    pthread_create(&thread, nullptr, process_files_thread, &thread_files[i]);
    threads.push_back(thread);
  }
  for (pthread_t t : threads) {
    pthread_join(t, nullptr);
  }

  map<string, FileInfo> file_info;
  for (auto& f : thread_files) {
    for (auto& ff : f) {
      file_info[ff.first.file_name] = ff.second;
    }
  }

  return file_info;
}

static bool is_in_trace_dir(const string& file_name, const string& trace_dir) {
  return file_name.find(trace_dir) == 0;
}

static string copy_into_trace(const string& file_name, const string& trace_dir,
                              int* name_index) {
  // We don't bother trying to do a reflink-copy here because if that was going
  // to succeed, rr would probably already have used it during recording.
  string new_name;
  ScopedFd out_fd;
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
  while (true) {
    char new_name_buf[PATH_MAX];
    snprintf(new_name_buf, sizeof(new_name_buf) - 1, "mmap_pack_%d_%s",
             *name_index, last_component);
    new_name_buf[sizeof(new_name_buf) - 1] = 0;
    new_name = trace_dir + "/" + new_name_buf;
    ++*name_index;
    out_fd = open(new_name.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0700);
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
    const string& trace_dir) {
  map<string, FileInfo> file_info = gather_file_info(trace_dir);

  map<FileHash, string> hash_to_name;
  for (auto& p : file_info) {
    const auto& existing = hash_to_name.find(p.second.hash);
    if (existing != hash_to_name.end()) {
      auto& info_existing = file_info[existing->second];
      if (!info_existing.is_hardlink &&
          is_in_trace_dir(existing->second, trace_dir)) {
        continue;
      }
    }
    hash_to_name[p.second.hash] = p.first;
  }

  int name_index = 0;
  for (auto& p : hash_to_name) {
    // Copy hardlinked files into the trace to avoid the possibility of someone
    // overwriting the original file.
    auto& info = file_info[p.second];
    if (info.is_hardlink || !is_in_trace_dir(p.second, trace_dir)) {
      p.second = copy_into_trace(p.second, trace_dir, &name_index);
    }
  }

  map<string, string> file_map;
  for (auto& p : file_info) {
    string name = hash_to_name[p.second.hash];
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
    KernelMapping km = trace.read_mapped_region(
        &data, &found, TraceReader::VALIDATE, TraceReader::ANY_TIME);
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
    TraceWriter::write_mapped_region_to_alternative_stream(writer, data, km);
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

static int pack(const string& trace_dir) {
  string dir;
  {
    // validate trace and produce default trace directory if trace_dir is empty
    TraceReader reader(trace_dir);
    dir = reader.dir();
  }

  char buf[PATH_MAX];
  char* ret = realpath(dir.c_str(), buf);
  if (!ret) {
    FATAL() << "realpath failed on " << dir;
  }
  string abspath(buf);
  map<string, string> canonical_mmapped_files =
      compute_canonical_mmapped_files(abspath);
  rewrite_mmaps(canonical_mmapped_files, abspath);
  delete_unnecessary_files(canonical_mmapped_files, abspath);

  if (!probably_not_interactive(STDOUT_FILENO)) {
    printf("rr: Packed trace directory `%s'.\n", dir.c_str());
  }

  return 0;
}

int PackCommand::run(vector<string>& args) {
  bool found_dir = false;
  string trace_dir;

  while (!args.empty()) {
    if (!found_dir && parse_optional_trace_dir(args, &trace_dir)) {
      found_dir = true;
      continue;
    }
    print_help(stderr);
    return 1;
  }

  return pack(trace_dir);
}

} // namespace rr
