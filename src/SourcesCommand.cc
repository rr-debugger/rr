/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include <dirent.h>
#include <spawn.h>
#include <unistd.h>

#include <algorithm>
#include <set>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <map>

#include "Command.h"
#include "ElfReader.h"
#include "Flags.h"
#include "ReplaySession.h"
#include "StringVectorToCharArray.h"
#include "TraceStream.h"
#include "core.h"
#include "cpp_supplement.h"
#include "log.h"
#include "main.h"
#include "util.h"

using namespace std;

namespace rr {

const char* DEBUGLINK = "debuglink";
const char* DEBUGALTLINK = "debugaltlink";
const char* DWP = "dwp";

/// Prints JSON containing
/// "relevant_binaries": an array of strings, trace-relative binary file names (or build-ids, for explicit-sources).
///   These are ELF files in the trace that our collected data is relevant to.
/// "loaded_elf_binaries": an array of strings of absolute paths.
///   These are the paths to all the loaded ELF objects mapped at any point in the trace, including both shared libraries and executables.
/// "external_debug_info": an array of objects, {"path":<path>, "build_id":<build-id>, "type":<type>}
///   These are ELF files in the filesystem that contain separate debuginfo. "build-id" is the
///   build-id of the file from whence it originated, as a string. "type" is the type of
///   external file, one of "debuglink", "debugaltlink", "dwp". Note that for "debugaltlink", it is possible
///   to have the same file appearing multiple times with different build-ids, when it's shared by
///   multiple ELF binaries.
/// "dwo": an array of objects, {"name":<name>, "trace_file":<name>, "build_id":<value>, "comp_dir":<path>, "id":<value>}
///   These are the references to DWO files found in the trace binaries. "name" is the value of
/// DW_AT_GNU_dwo_name. "trace_file" is the trace-relative binary file name. "build_id" is the
/// binary's ELF build-id. "comp_dir" is the value of DW_AT_comp_dir for the compilation unit
/// containing the DWO reference. "id" is the value of DW_AT_GNU_dwo_id (64 bit number).
/// "symlinks": an array of objects, {"from":<path>, "to":<path>}.
///   These symlinks that exist in the filesystem that are relevant to the source file paths.
/// "files": a map from VCS directory name to array of source files relative to that directory
///   An empty VCS directory name means files not under any VCS.
/// "comp_dir_substitutions": a map from trace-relative binary file names (or build-ids, for explicit-sources) to
/// the compilation-dir-override.
class SourcesCommand : public Command {
public:
  virtual int run(vector<string>& args) override;

protected:
  SourcesCommand(const char* name, const char* help) : Command(name, help) {}

  static SourcesCommand singleton;
};

SourcesCommand SourcesCommand::singleton(
    "sources",
    " rr sources [<trace_dir>]\n"
    "  --substitute=LIBRARY=PATH  When searching for the source to LIBRARY,\n"
    "                             substitute PATH in place of the path stored\n"
    "                             in the library's DW_AT_comp_dir property\n"
    "                             for all compilation units.\n"
    "                             LIBRARY is the basename of the original file name,\n"
    "                             e.g. libc-2.32.so\n"
    "  --gdb-script=SCRIPT        Runs the provided gdb script in a (very basic)\n"
    "                             emulator, and gives it a chance to change paths\n"
    "                             for symbol loading/etc\n");

class ExplicitSourcesCommand : public Command {
public:
  virtual int run(vector<string>& args) override;

protected:
  ExplicitSourcesCommand(const char* name, const char* help) : Command(name, help) {}

  static ExplicitSourcesCommand singleton;
};

ExplicitSourcesCommand ExplicitSourcesCommand::singleton(
    "explicit-sources",
    " rr explicit-sources [<file>...]\n"
    "  Like `rr sources` but instead of scanning the binary files used in a\n"
    "  trace, scans an explicit list of files.\n"
    "  --substitute=LIBRARY=PATH  When searching for the source to LIBRARY,\n"
    "                             substitute PATH in place of the path stored\n"
    "                             in the library's DW_AT_comp_dir property\n"
    "                             for all compilation units.\n"
    "                             LIBRARY is the basename of the original file name,\n"
    "                             e.g. libc-2.32.so\n");

struct SourcesFlags {
  map<string, string> comp_dir_substitutions;
  string gdb_script;
};

static void dir_name(string& s) {
  size_t p = s.rfind('/');
  if (p == string::npos || (p == 0 && s.size() == 1)) {
    s.clear();
  } else if (p > 0) {
    s.resize(p);
  } else {
    s.resize(1);
  }
}

static bool is_absolute(const string& s) {
  return s[0] == '/';
}

static void prepend_path(const char* prefix, string& s) {
  size_t len = strlen(prefix);
  if (!len) {
    return;
  }
  if (prefix[len - 1] == '/') {
    s = string(prefix) + s;
  } else {
    s = string(prefix) + '/' + s;
  }
}

struct DirExistsCache {
  unordered_map<string, bool> cache;
  bool dir_exists(const string& dir) {
    auto it = cache.find(dir);
    if (it != cache.end()) {
      return it->second;
    }
    bool exists = access(dir.c_str(), F_OK) == 0;
    cache.insert(make_pair(dir, exists));
    return exists;
  }
};

struct DebugDirs {
  vector<string> debug_file_directories;
  vector<string> source_directories;
};

/// Manages integration with rr-gdb-script-host.py to allow a gdb script to
/// control which directories we search. If input_pipe_fd is open we have a
/// python child process. If input_pipe_fd is closed then everything here
/// becomes a no-op.
class DebugDirManager {
public:
  DebugDirManager(const string& program, const string& gdb_script);
  ~DebugDirManager();

  DebugDirs initial_directories() {
    if (!input_pipe_fd.is_open()) {
      // Try known alternatives.
      if (char* nix_debug_info_dirs = getenv("NIX_DEBUG_INFO_DIRS")) {
        // NIX_DEBUG_INFO_DIRS is a colon separated list of paths to search for debug info.
        DebugDirs result;

        // Make a copy that we can run strtok on.
        nix_debug_info_dirs = strdup(nix_debug_info_dirs);
        char* token = strtok(nix_debug_info_dirs, ":");
        while (token != nullptr) {
          string s(token);
          s = real_path(s);
          result.debug_file_directories.push_back(s);
          LOG(debug) << "NIX_DEBUG_INFO_DIRS added debug dir '" << s << "'";
          token = strtok(nullptr, ":");
        }
        free(nix_debug_info_dirs);
        return result;
      }
    }

    return read_result();
  }
  DebugDirs process_one_binary(const string& binary_path);

private:
  DebugDirManager(const DebugDirManager&) = delete;
  DebugDirManager& operator=(const DebugDirManager&) = delete;

  DebugDirs read_result();

  ScopedFd input_pipe_fd;
  FILE* output_file;
  pid_t pid;
};

DebugDirManager::~DebugDirManager() {
  if (!input_pipe_fd.is_open()) {
    return;
  }

  input_pipe_fd.close();
  fclose(output_file);

  int status;
  if (waitpid(pid, &status, 0) == -1) {
    FATAL() << "Failed to wait on gdb script host";
  }
}

DebugDirManager::DebugDirManager(const string& program, const string& gdb_script)
  : pid(-1)
{
  if (gdb_script.empty()) {
    return;
  }

  int stdin_pipe_fds[2];
  if (pipe(stdin_pipe_fds) == -1) {
    FATAL();
  }
  int stdout_pipe_fds[2];
  if (pipe(stdout_pipe_fds) == -1) {
    FATAL();
  }

  posix_spawn_file_actions_t file_actions;
  int ret = posix_spawn_file_actions_init(&file_actions);
  if (ret != 0) {
    FATAL() << "posix_spawn_file_actions_init failed with " << ret;
  }

  // Close unused write end in the child.
  ret = posix_spawn_file_actions_addclose(&file_actions, stdin_pipe_fds[1]);
  if (ret != 0) {
    FATAL() << "posix_spawn_file_actions_addclose failed with " << ret;
  }

  // Close unused read end in the child.
  ret = posix_spawn_file_actions_addclose(&file_actions, stdout_pipe_fds[0]);
  if (ret != 0) {
    FATAL() << "posix_spawn_file_actions_addclose failed with " << ret;
  }

  // Replace child's stdin with the read end.
  ret = posix_spawn_file_actions_adddup2(&file_actions, stdin_pipe_fds[0], 0);
  if (ret != 0) {
    FATAL() << "posix_spawn_file_actions_adddup2 failed with " << ret;
  }

  // Replace child's stdout with the write end.
  ret = posix_spawn_file_actions_adddup2(&file_actions, stdout_pipe_fds[1], 1);
  if (ret != 0) {
    FATAL() << "posix_spawn_file_actions_adddup2 failed with " << ret;
  }

  string gdb_script_host_path = resource_path() + "bin/rr-gdb-script-host.py";
  pid_t pid;
  vector<string> gdb_script_host_argv_vec = { gdb_script_host_path, gdb_script, program };
  StringVectorToCharArray gdb_script_host_argv(gdb_script_host_argv_vec);
  ret = posix_spawn(&pid, gdb_script_host_path.c_str(), &file_actions, nullptr,
                    gdb_script_host_argv.get(), environ);
  if (ret != 0) {
    FATAL() << "posix_spawn failed with " << ret;
  }

  // Ignore the return values during cleanup.
  posix_spawn_file_actions_destroy(&file_actions);

  close(stdin_pipe_fds[0]);
  close(stdout_pipe_fds[1]);

  this->pid = pid;
  this->input_pipe_fd = ScopedFd(stdin_pipe_fds[1]);
  this->output_file = fdopen(stdout_pipe_fds[0], "r");
  if (!this->output_file) {
    FATAL() << "Failed to fdopen(stdout_pipe_fds[0])";
  }
}

DebugDirs DebugDirManager::process_one_binary(const string& binary_path) {
  if (!input_pipe_fd.is_open()) {
    return DebugDirs();
  }

  auto len = binary_path.length();
  size_t written = write(input_pipe_fd, binary_path.c_str(), len);
  if (written != len) {
    FATAL() << "Failed to write filename";
  }
  written = write(input_pipe_fd, "\n", 1);
  if (written != 1) {
    FATAL() << "Failed to write trailing newline";
  }

  return read_result();
}

DebugDirs DebugDirManager::read_result() {
  char buf[4096];
  DebugDirs result;
  size_t index;
  const char delimiter[2] = ":";

  if (!input_pipe_fd.is_open()) {
    return result;
  }

  if (!fgets(buf, sizeof(buf) - 1, output_file)) {
    FATAL() << "Failed to read gdb script output";
  }
  index = strcspn(buf, "\n");
  buf[index] = 0;

  char* token = strtok(buf, delimiter);
  while (token != nullptr) {
    string s(token);
    s = real_path(s);
    result.debug_file_directories.push_back(s);
    LOG(debug) << "gdb script added debug dir '" << s << "'";
    token = strtok(nullptr, delimiter);
  }

  if (!fgets(buf, sizeof(buf) - 1, output_file)) {
    FATAL() << "Failed to read gdb script output";
  }
  index = strcspn(buf, "\n");
  buf[index] = 0;

  token = strtok(buf, delimiter);
  while (token != nullptr) {
    char* buf = realpath(token, nullptr);
    if (buf) {
      auto s = string(buf);
      result.source_directories.push_back(s);
      LOG(debug) << "gdb script added source dir '" << s << "'";
      free(buf);
    } else {
      LOG(debug) << "realpath(" << token << ") = " << strerror(errno);
    }
    token = strtok(nullptr, delimiter);
  }

  return result;
}

// Resolve a file name relative to a compilation directory and relative directory.
// file_name cannot be null, but the others can be.
// Takes into account the original file name as follows:
// -- if comp_dir, rel_dir or file_name are absolute, or original_file_name is NULL,
// then ignore original_file_name.
// The result is just the result of combining comp_dir/rel_dir/file_name.
// -- otherwise they're all relative to some build directory. We hypothesize
// the build directory is some ancestor directory of original_file_name.
// We try making comp_dir/rel_dir/file_name relative to each ancestor directory
// of original_file_name, and if we find a file there, we return that name.
// original_file_name must be absolute if not NULL.
//
// If non-empty, `comp_dir_substitution` should replace `original_comp_dir`
// in `rel_dir` if `original_comp_dir` is a prefix of `rel_dir`.
// Always returns an absolute file name.
// Returns true if we got a result, otherwise false.
static bool resolve_file_name(const char* original_file_name,
                              const char* comp_dir,
                              const char* original_comp_dir,
                              const string& comp_dir_substitution,
                              const char* rel_dir,
                              const char* file_name,
                              DirExistsCache& dir_exists_cache,
                              string& path) {
  path = file_name;
  if (is_absolute(path)) {
    return true;
  }
  if (rel_dir) {
    if (rel_dir[0] == '/' && !comp_dir_substitution.empty() && original_comp_dir &&
        strncmp(rel_dir, original_comp_dir, strlen(original_comp_dir)) == 0) {
      string rel = comp_dir_substitution + (rel_dir + strlen(original_comp_dir));
      prepend_path(rel.c_str(), path);
    } else {
      prepend_path(rel_dir, path);
    }
    if (is_absolute(path)) {
      return true;
    }
  }
  if (comp_dir) {
    prepend_path(comp_dir, path);
    if (is_absolute(path)) {
      return true;
    }
  }
  if (!original_file_name) {
    if (is_absolute(path)) {
      return true;
    }
    LOG(warn) << "Path " << path << " is relative and we can't make it absolute";
    return false;
  }
  string original(original_file_name);
  while (true) {
    dir_name(original);
    if (original.empty()) {
      LOG(warn) << "Path " << path << " is relative and we can't make it absolute";
      return false;
    }
    string candidate = original + "/" + path;
    if (dir_exists_cache.dir_exists(candidate)) {
      path = candidate;
      return true;
    }
  }
}

struct DwoInfo {
  string name;
  string trace_file;
  string build_id;
  // Could be an empty string
  string comp_dir;
  string full_path;
  uint64_t id;
};

struct OutputCompDirSubstitution {
  string trace_relative_name;
  string substitution;
};

static bool process_compilation_units(ElfFileReader& reader,
                                      ElfFileReader* sup_reader,
                                      const string& trace_relative_name,
                                      const string& original_file_name,
                                      const string& comp_dir_substitution,
                                      vector<OutputCompDirSubstitution>& comp_dir_substitutions,
                                      const string* debug_file_directory,
                                      const string* debug_src_directory,
                                      set<string>* file_names, vector<DwoInfo>* dwos,
                                      DirExistsCache& dir_exists_cache) {
  string build_id = reader.read_buildid();
  DwarfSpan debug_info = reader.dwarf_section(".debug_info");
  if (debug_info.empty()) {
    debug_info = reader.dwarf_section(".zdebug_info", true);
  }
  DwarfSpan debug_abbrev = reader.dwarf_section(".debug_abbrev");
  if (debug_abbrev.empty()) {
    debug_abbrev = reader.dwarf_section(".zdebug_abbrev", true);
  }
  DwarfSpan debug_str = reader.dwarf_section(".debug_str");
  if (debug_str.empty()) {
    debug_str = reader.dwarf_section(".zdebug_str", true);
  }
  DwarfSpan debug_str_sup = sup_reader ? sup_reader->dwarf_section(".debug_str") : DwarfSpan();
  DwarfSpan debug_str_offsets = reader.dwarf_section(".debug_str_offsets");
  DwarfSpan debug_line = reader.dwarf_section(".debug_line");
  if (debug_line.empty()) {
    debug_line = reader.dwarf_section(".zdebug_line", true);
  }
  DwarfSpan debug_line_str = reader.dwarf_section(".debug_line_str");
  if (debug_info.empty() || debug_abbrev.empty() ||
      (debug_str.empty() && debug_str_sup.empty()) ||
      debug_line.empty())  {
    return false;
  }

  DebugStrSpans debug_strs = {
    debug_str,
    debug_str_sup,
    debug_str_offsets,
    debug_line_str,
  };

  DwarfAbbrevs abbrevs(debug_abbrev);
  do {
    bool ok = true;
    DwarfCompilationUnit cu = DwarfCompilationUnit::next(&debug_info, abbrevs, &ok);
    if (!ok) {
      break;
    }
    int64_t str_offsets_base = cu.die().section_ptr_attr(DW_AT_str_offsets_base, &ok);
    if (!ok) {
      continue;
    }
    if (str_offsets_base > 0) {
      cu.set_str_offsets_base(str_offsets_base);
    } else {
      cu.set_str_offsets_base(0);
    }
    const char* original_comp_dir = cu.die().string_attr(cu, DW_AT_comp_dir, debug_strs, &ok);
    string comp_dir;
    if (!comp_dir_substitution.empty()) {
      comp_dir = comp_dir_substitution;
    } else {
      if (!ok) {
        continue;
      }
      if (original_comp_dir) {
        comp_dir = original_comp_dir;
      }
      if (debug_src_directory && !is_absolute(comp_dir)) {
        prepend_path(debug_src_directory->c_str(), comp_dir);
        if (std::find_if(comp_dir_substitutions.begin(), comp_dir_substitutions.end(), [trace_relative_name](OutputCompDirSubstitution& s) {
          return s.trace_relative_name == trace_relative_name;
        }) == comp_dir_substitutions.end()) {
          comp_dir_substitutions.push_back({ trace_relative_name, comp_dir });
        }
      } else if (debug_file_directory) {
        prepend_path(debug_file_directory->c_str(), comp_dir);
      }
    }
    const char* dwo_name = cu.die().string_attr(cu, DW_AT_GNU_dwo_name, debug_strs, &ok);
    if (!ok || !dwo_name) {
      dwo_name = cu.die().string_attr(cu, DW_AT_dwo_name, debug_strs, &ok);
      if (!ok) {
        continue;
      }
    }
    if (dwo_name) {
      bool has_dwo_id = false;
      uint64_t dwo_id = cu.dwo_id();
      if (dwo_id != 0) {
        has_dwo_id = true;
      }
      if (!has_dwo_id) {
        dwo_id = cu.die().unsigned_attr(DW_AT_GNU_dwo_id, &has_dwo_id, &ok);
        if (!ok) {
          LOG(warn) << "Have DWO name " << dwo_name << " but can't get DWO id";
          continue;
        }
      }
      if (has_dwo_id) {
        string full_name;
        LOG(debug) << "Have DWO name " << dwo_name << " id " << HEX(dwo_id);
        if (resolve_file_name(original_file_name.c_str(), comp_dir.c_str(), original_comp_dir, comp_dir_substitution, nullptr, dwo_name, dir_exists_cache, full_name)) {
          string c = comp_dir;
          dwos->push_back({ dwo_name, trace_relative_name, build_id, std::move(c), full_name, dwo_id });
        } else {
          FATAL() << "DWO missing due to relative path " << full_name;
        }
      } else {
        LOG(warn) << "DW_AT_GNU_dwo_name but not DW_AT_GNU_dwo_id";
      }
    }
    const char* source_file_name = cu.die().string_attr(cu, DW_AT_name, debug_strs, &ok);
    if (!ok) {
      continue;
    }
    if (source_file_name) {
      string full_name;
      if (resolve_file_name(original_file_name.c_str(), comp_dir.c_str(), original_comp_dir, comp_dir_substitution, nullptr, source_file_name, dir_exists_cache, full_name)) {
        file_names->insert(full_name);
      }
    }
    intptr_t stmt_list = cu.die().section_ptr_attr(DW_AT_stmt_list, &ok);
    if (stmt_list < 0 || !ok) {
      continue;
    }
    DwarfLineNumberTable lines(cu, debug_line.subspan(stmt_list), debug_strs, &ok);
    if (!ok) {
      continue;
    }
    for (auto& f : lines.file_names()) {
      if (!f.file_name) {
        // Already resolved above.
        continue;
      }
      const char* dir = lines.directories()[f.directory_index];
      string full_name;
      if (resolve_file_name(original_file_name.c_str(), comp_dir.c_str(), original_comp_dir, comp_dir_substitution, dir, f.file_name, dir_exists_cache, full_name)) {
        file_names->insert(full_name);
      }
    }
  } while (!debug_info.empty());

  return true;
}

struct ExternalDebugInfo {
  string path;
  string build_id;
  string type;
  bool operator<(const ExternalDebugInfo& other) const {
    if (path < other.path) {
      return true;
    }
    if (path > other.path) {
      return false;
    }
    if (build_id < other.build_id) {
      return true;
    }
    if (build_id > other.build_id) {
      return false;
    }
    return type < other.type;
  }
};

static unique_ptr<ElfFileReader>
find_auxiliary_file(const string& original_file_name,
                    const string& aux_file_name,
                    string& full_file_name,
                    const vector<string>& dirs) {
  if (aux_file_name.empty()) {
    return nullptr;
  }
  ScopedFd fd;
  if (aux_file_name.c_str()[0] == '/') {
    full_file_name = aux_file_name;
    fd = ScopedFd(full_file_name.c_str(), O_RDONLY);
    if (!fd.is_open()) {
      LOG(warn) << "Can't find external debuginfo file " << full_file_name;
      return nullptr;
    }
  } else {
    // Skip first trying the current directory. That's unlikely to be correct.

    // Try in the same directory as the original file.
    string original_file_dir = original_file_name;
    dir_name(original_file_dir);
    full_file_name = original_file_dir + "/" + aux_file_name;
    normalize_file_name(full_file_name);
    fd = ScopedFd(full_file_name.c_str(), O_RDONLY);
    if (fd.is_open()) {
      // Debian/Ubuntu built /lib/x86_64-linux-gnu/ld-2.31.so with a
      // .gnu_debuglink of "ld-2.31.so", expecting it to be found at
      // /usr/lib/debug/lib/x86_64-linux-gnu/ld-2.31.so. So we need to make
      // sure we aren't using the binary file as its own debuginfo.
      if (real_path(original_file_name) != real_path(full_file_name)) {
        goto found;
      }
    }
    LOG(info) << "Can't find external debuginfo file " << full_file_name;

    // Next try in a subdirectory called .debug
    full_file_name = original_file_dir + "/.debug/" + aux_file_name;
    normalize_file_name(full_file_name);
    fd = ScopedFd(full_file_name.c_str(), O_RDONLY);
    if (fd.is_open()) {
      goto found;
    }
    LOG(info) << "Can't find external debuginfo file " << full_file_name;

    // Then try in /usr/lib/debug
    full_file_name = "/usr/lib/debug/" + aux_file_name;
    normalize_file_name(full_file_name);
    fd = ScopedFd(full_file_name.c_str(), O_RDONLY);
    if (fd.is_open()) {
      goto found;
    }
    LOG(info) << "Can't find external debuginfo file " << full_file_name;

    // Try in an appropriate subdirectory of /usr/lib/debug
    full_file_name = "/usr/lib/debug" + original_file_dir + "/" + aux_file_name;
    normalize_file_name(full_file_name);
    fd = ScopedFd(full_file_name.c_str(), O_RDONLY);
    if (fd.is_open()) {
      goto found;
    }
    LOG(info) << "Can't find external debuginfo file " << full_file_name;

    // Try in an appropriate subdirectory of the provided debug dirs
    for (auto& d : dirs) {
      full_file_name = d + original_file_dir + "/" + aux_file_name;
      normalize_file_name(full_file_name);
      fd = ScopedFd(full_file_name.c_str(), O_RDONLY);
      if (fd.is_open()) {
        goto found;
      }
      LOG(info) << "Can't find external debuginfo file " << full_file_name;
    }

    // On Ubuntu 20.04 there's both a /lib/x86_64-linux-gnu/libc-2.31.so and a
    // /usr/lib/x86_64-linux-gnu/libc-2.31.so. They are hardlinked to the same inode,
    // and glibc debuginfo is present in the location corresponding to
    // /lib/x86_64-linux-gnu/libc-2.31.so. But the kernel returns the /usr prefixed
    // path from /proc/<pid>/fd/<fd>. Hack around that here.
    if (original_file_dir.find("/usr/") == 0) {
      full_file_name = "/usr/lib/debug" + original_file_dir.substr(sizeof("/usr") - 1) + "/" + aux_file_name;
      normalize_file_name(full_file_name);
      fd = ScopedFd(full_file_name.c_str(), O_RDONLY);
      if (fd.is_open()) {
        goto found;
      }
      LOG(info) << "Can't find external debuginfo file " << full_file_name;
    }

    // If none of those worked, give up.
    LOG(warn) << "Exhausted auxiliary debuginfo search locations for " << aux_file_name;
    return nullptr;
  }

found:
  LOG(info) << "Examining external " << full_file_name;
  auto reader = make_unique<ElfFileReader>(fd);
  if (!reader->ok()) {
    LOG(warn) << "Not an ELF file!";
    return nullptr;
  }
  return reader;
}

static unique_ptr<ElfFileReader>
find_auxiliary_file_by_buildid(ElfFileReader& trace_file_reader,
                               string& full_file_name,
                               const vector<string>& dirs) {
  string build_id = trace_file_reader.read_buildid();
  if (build_id.empty()) {
    LOG(warn) << "Main ELF binary has no build ID!";
    return nullptr;
  }
  if (build_id.size() < 3) {
    LOG(warn) << "Build ID is too short!";
    return nullptr;
  }

  string filename = build_id.substr(0, 2) + "/" + build_id.substr(2) + ".debug";
  string path = "/usr/lib/debug/.build-id/" + filename;
  ScopedFd fd(path.c_str(), O_RDONLY);
  if (!fd.is_open()) {
    LOG(info) << "Can't find external debuginfo file " << path;
    for (auto &d : dirs) {
      path = d + "/.build-id/" + filename;
      fd = ScopedFd(path.c_str(), O_RDONLY);
      if (fd.is_open()) {
        break;
      }
      LOG(info) << "Can't find external debuginfo file " << path;
    }
  }

  if (!fd.is_open()) {
    return nullptr;
  }

  LOG(info) << "Examining external by buildid " << path;
  auto reader = make_unique<ElfFileReader>(fd);
  if (!reader->ok()) {
    LOG(warn) << "Not an ELF file!";
    return nullptr;
  }
  full_file_name = path;
  return reader;
}

// Traverse the compilation units of an auxiliary file to collect their source files
static bool process_auxiliary_file(ElfFileReader& trace_file_reader,
                                   ElfFileReader& aux_file_reader,
                                   ElfFileReader* alt_file_reader,
                                   const string& trace_relative_name,
                                   const string& original_file_name,
                                   set<string>* file_names,
                                   const string& full_aux_file_name,
                                   const char* file_type,
                                   map<string, string> comp_dir_substitutions,
                                   vector<OutputCompDirSubstitution>& output_comp_dir_substitutions,
                                   const string* chosen_debug_dir,
                                   const string* chosen_src_dir,
                                   vector<DwoInfo>* dwos,
                                   set<ExternalDebugInfo>* external_debug_info,
                                   bool already_used_file,
                                   DirExistsCache& dir_exists_cache) {
  string build_id = trace_file_reader.read_buildid();
  if (build_id.empty()) {
    LOG(warn) << "Main ELF binary has no build ID!";
    return false;
  }

  bool did_work;
  string original_name = original_file_name;
  base_name(original_name);
  auto it = comp_dir_substitutions.find(original_name);
  if (it != comp_dir_substitutions.end()) {
    LOG(debug) << "\tFound comp_dir substitution " << it->second;
    did_work = process_compilation_units(aux_file_reader, alt_file_reader,
                                         trace_relative_name, original_file_name,
                                         it->second, output_comp_dir_substitutions,
                                         chosen_debug_dir, chosen_src_dir,
                                         file_names, dwos, dir_exists_cache);
  } else {
    LOG(debug) << "\tNo comp_dir substitution found";
    did_work = process_compilation_units(aux_file_reader, alt_file_reader,
                                         trace_relative_name, original_file_name,
                                         {}, output_comp_dir_substitutions,
                                         chosen_debug_dir, chosen_src_dir,
                                         file_names, dwos, dir_exists_cache);
  }

  if (!did_work) {
    LOG(warn) << "No debuginfo!";
    /* If we've already used this file we need to insert it into the external_debug_info
     * set even if it does not have any CUs of its own.
     */
    if (!already_used_file) {
      return false;
    }
  }
  external_debug_info->insert({ full_aux_file_name, build_id, string(file_type) });
  return did_work;
}

static bool try_debuglink_file(ElfFileReader& trace_file_reader,
                               const string& trace_relative_name,
                               const string& original_file_name,
                               set<string>* file_names, const string& aux_file_name,
                               map<string, string>& comp_dir_substitutions,
                               vector<OutputCompDirSubstitution>& output_comp_dir_substitutions,
                               unique_ptr<DebugDirManager>& debug_dirs,
                               DebugDirs& dd,
                               vector<DwoInfo>* dwos,
                               set<ExternalDebugInfo>* external_debug_info,
                               DirExistsCache& dir_exists_cache) {
  string full_file_name;
  auto reader = find_auxiliary_file(original_file_name, aux_file_name,
                                    full_file_name, dd.debug_file_directories);
  if (!reader) {
    reader = find_auxiliary_file_by_buildid(trace_file_reader, full_file_name, dd.debug_file_directories);
    if (!reader) {
      dd.debug_file_directories.clear();
      dd.source_directories.clear();
      return false;
    }
  }

  if (debug_dirs) {
    dd = debug_dirs->process_one_binary(full_file_name);
  }

  /* A debuglink file can have its own debugaltlink */
  string full_altfile_name;
  Debugaltlink debugaltlink = reader->read_debugaltlink();
  auto altlink_reader = find_auxiliary_file(original_file_name, debugaltlink.file_name,
                                            full_altfile_name, dd.debug_file_directories);

  // Notify a gdb script about the main binary before processing CUs.
  if (debug_dirs) {
    dd = debug_dirs->process_one_binary(original_file_name);
  }

  vector<string*> debug_file_directories;
  debug_file_directories.reserve(dd.debug_file_directories.size() + 1);
  for (auto& dfd : dd.debug_file_directories) {
    debug_file_directories.push_back(&dfd);
  }
  debug_file_directories.push_back(nullptr);

  for (auto chosen_debug_dir : debug_file_directories) {
    const string* chosen_src_dir = nullptr;
    if (!dd.source_directories.empty()) {
      chosen_src_dir = &dd.source_directories.back();
    }

    bool has_source_files = process_auxiliary_file(trace_file_reader, *reader, altlink_reader.get(),
                                                   trace_relative_name, original_file_name,
                                                   file_names, full_file_name, DEBUGLINK,
                                                   comp_dir_substitutions, output_comp_dir_substitutions,
                                                   chosen_debug_dir, chosen_src_dir,
                                                   dwos, external_debug_info, false, dir_exists_cache);

    if (altlink_reader) {
      has_source_files |= process_auxiliary_file(trace_file_reader, *altlink_reader, nullptr,
                                                 trace_relative_name, original_file_name,
                                                 file_names, full_altfile_name, DEBUGALTLINK,
                                                 comp_dir_substitutions, output_comp_dir_substitutions,
                                                 chosen_debug_dir, chosen_src_dir,
                                                 dwos, external_debug_info, has_source_files, dir_exists_cache);
    }
    if (has_source_files) {
      return true;
    }
  }
  return false;
}

struct Symlink {
  string from;
  string to;
};

static bool has_subdir(string& base, const char* suffix) {
  base += suffix;
  int ret = access(base.c_str(), F_OK);
  base.resize(base.size() - strlen(suffix));
  return !ret;
}

static void assert_absolute(const string& path) {
  if (!is_absolute(path)) {
    FATAL() << "Path " << path << " not absolute";
  }
}

static void check_vcs_root(string& path, set<string>* vcs_dirs) {
  assert_absolute(path);
  if (has_subdir(path, "/.git") || has_subdir(path, "/.hg")) {
    vcs_dirs->insert(path + "/");
  }
}

// Returns an empty string if the path does not exist or
// is not accessible.
// `path` need not be normalized, i.e. may contain .. or .
// components. It mus be absolute.
// The result string, if non-empty, will be absolute,
// normalized, and contain no symlink components.
// The keys in resolved_dirs are absolute file paths
// that may contain symlink components and need not be
// normalized.
// The values in resolved_dirs are always absolute, normalized,
// contain no symlink components, and are directories.
static string resolve_symlinks(const string& path,
                               bool is_file,
                               unordered_map<string, string>* resolved_dirs,
                               vector<Symlink>* symlinks,
                               set<string>* vcs_dirs) {
  assert_absolute(path);
  // Absolute, not normalized. We don't keep this normalized because
  // we want resolved_dirs to work well.
  // This is always a prefix of `path`.
  string base = path;
  // Absolute, normalized, no symlink components.
  string resolved_base;
  string rest;
  while (true) {
    size_t p = base.rfind('/');
    if (p == 0 || p == string::npos) {
      base = "";
      rest = path;
      break;
    }
    base.resize(p - 1);
    auto it = resolved_dirs->find(base);
    if (it != resolved_dirs->end()) {
      resolved_base = it->second;
      rest = path.substr(p);
      break;
    }
  }
  // Now iterate through the components of "rest".
  // p points to some '/'-starting component in `rest`.
  size_t p = 0;
  while (true) {
    size_t next = rest.find('/', p + 1);
    bool base_is_file = false;
    size_t end;
    if (next == string::npos) {
      base.append(rest, p, rest.size() - p);
      resolved_base.append(rest, p, rest.size() - p);
      base_is_file = is_file;
      end = rest.size();
    } else {
      base.append(rest, p, next - p);
      resolved_base.append(rest, p, next - p);
      end = next;
    }

    if ((end == p + 2 && memcmp(rest.c_str() + p, "/.", 2) == 0) ||
        (end == p + 3 && memcmp(rest.c_str() + p, "/..", 3) == 0)) {
      normalize_file_name(resolved_base);
    }

    p = next;

    // Now make resolved_base actually resolved.
    // First see if our new resolved_base is cached.
    auto it = resolved_dirs->find(resolved_base);
    if (it != resolved_dirs->end()) {
      resolved_base = it->second;
      if (next == string::npos) {
        return resolved_base;
      }
      resolved_dirs->insert(make_pair(base, resolved_base));
      continue;
    }

    char buf[PATH_MAX + 1];
    ssize_t ret = readlink(resolved_base.c_str(), buf, sizeof(buf));
    if (ret >= 0) {
      buf[ret] = 0;
      string target;
      if (buf[0] != '/') {
        target = base;
        dir_name(target);
        if (target.size() > 1) {
          target.push_back('/');
        }
      }
      target += buf;
      // We can't normalize `target` because `buf` may itself contain
      // unresolved symlinks, which make normalization non-semantics-preserving.
      string resolved = resolve_symlinks(target, base_is_file, resolved_dirs, symlinks, vcs_dirs);
      symlinks->push_back({ resolved_base, resolved });
      if (!base_is_file) {
        check_vcs_root(resolved, vcs_dirs);
        // Cache the result of the readlink operation
        resolved_dirs->insert(make_pair(std::move(resolved_base), resolved));
        // And cache based on the original `base`.
        resolved_dirs->insert(make_pair(base, resolved));
      }
      resolved_base = resolved;
      if (next == string::npos) {
        return resolved_base;
      }
    } else {
      if (errno == ENOENT || errno == EACCES || errno == ENOTDIR) {
        // Path is invalid
        resolved_base.clear();
        return resolved_base;
      }
      if (errno != EINVAL) {
        FATAL() << "Failed to readlink " << base;
      }
      if (!base_is_file) {
        check_vcs_root(resolved_base, vcs_dirs);
        // Cache the result of the readlink operation
        resolved_dirs->insert(make_pair(resolved_base, resolved_base));
        // And cache based on the original `base`.
        resolved_dirs->insert(make_pair(base, resolved_base));
      }
      if (next == string::npos) {
        return resolved_base;
      }
    }
  }
}

/// Adds to vcs_dirs any directory paths under any
/// of our resolved directories.
/// file_names must be absolute.
static void build_symlink_map(const set<string>& file_names,
                              set<string>* resolved_file_names,
                              vector<Symlink>* symlinks,
                              set<string>* vcs_dirs) {
  // <dir> -> <path> --- <dir> resolves to <path> using the
  // current value of `symlinks` (and <path> contains no symlinks).
  // If <path> is the empty string then that means the same as <dir>.
  unordered_map<string, string> resolved_dirs;
  for (auto& file_name : file_names) {
    string resolved = resolve_symlinks(file_name, true, &resolved_dirs, symlinks, vcs_dirs);
    if (resolved.empty()) {
      LOG(info) << "File " << file_name << " not found, skipping";
    } else {
      LOG(debug) << "File " << file_name << " resolved to " << resolved;
      resolved_file_names->insert(resolved);
    }
  }
}

static bool starts_with(const string& s, const string& prefix) {
  return strncmp(s.c_str(), prefix.c_str(), prefix.size()) == 0;
}

template<class iterable>
static int sources(const iterable& binary_file_names,
                   map<string, string>& comp_dir_substitutions,
                   unique_ptr<DebugDirManager>& debug_dirs,
                   bool is_explicit) {
  vector<string> relevant_binary_names;
  set<string> original_loaded_elf_names;
  // Must be absolute.
  set<string> file_names;
  set<ExternalDebugInfo> external_debug_info;
  vector<DwoInfo> dwos;
  vector<OutputCompDirSubstitution> output_comp_dir_substitutions;
  DirExistsCache dir_exists_cache;
  DebugDirs dd;
  if (debug_dirs) {
    dd = debug_dirs->initial_directories();
  }

  for (auto& pair : binary_file_names) {
    string trace_relative_name = pair.first;
    string original_name = pair.second;
    const char* file_name = is_explicit ? original_name.c_str() : trace_relative_name.c_str();
    ScopedFd fd(file_name, O_RDONLY);
    if (!fd.is_open()) {
      FATAL() << "Can't open " << file_name;
    }
    LOG(info) << "Examining " << file_name;
    ElfFileReader reader(fd);
    if (!reader.ok()) {
      LOG(info) << "Probably not an ELF file, skipping";
      continue;
    }

    if (!is_explicit) {
      base_name(trace_relative_name);
    }
    original_loaded_elf_names.insert(original_name);
    base_name(original_name);
    Debugaltlink debugaltlink = reader.read_debugaltlink();

    string full_altfile_name;
    auto altlink_reader = find_auxiliary_file(pair.second, debugaltlink.file_name,
                                              full_altfile_name, dd.debug_file_directories);

    bool has_source_files;
    auto dwo_count = dwos.size();
    LOG(debug) << "Looking for comp_dir substitutions for " << original_name;
    auto it = comp_dir_substitutions.find(original_name);
    if (it != comp_dir_substitutions.end()) {
      LOG(debug) << "\tFound comp_dir substitution " << it->second;
      output_comp_dir_substitutions.push_back({ trace_relative_name, it->second });
      has_source_files = process_compilation_units(reader, altlink_reader.get(),
                                                   trace_relative_name, pair.second,
                                                   it->second, output_comp_dir_substitutions,
                                                   nullptr, nullptr, &file_names, &dwos,
                                                   dir_exists_cache);
    } else {
      LOG(debug) << "\tNo comp_dir substitution found";
      has_source_files = process_compilation_units(reader, altlink_reader.get(),
                                                   trace_relative_name, pair.second,
                                                   {}, output_comp_dir_substitutions,
                                                   nullptr, nullptr, &file_names, &dwos,
                                                   dir_exists_cache);
    }
    /* If the original binary had source files, force the inclusion of any debugaltlink
     * file, even if it does not itself have compilation units (it may have relevant strings)
     */
    const bool original_had_source_files = has_source_files;

    Debuglink debuglink = reader.read_debuglink();
    has_source_files |= try_debuglink_file(reader, trace_relative_name, pair.second,
                                           &file_names, debuglink.file_name,
                                           comp_dir_substitutions, output_comp_dir_substitutions, debug_dirs, dd, &dwos,
                                           &external_debug_info, dir_exists_cache);

    if (dd.debug_file_directories.empty() && debug_dirs) {
      dd = debug_dirs->process_one_binary(pair.first);
    }

    if (altlink_reader) {
      has_source_files |= process_auxiliary_file(reader, *altlink_reader, nullptr,
                                                 trace_relative_name, pair.second,
                                                 &file_names, full_altfile_name,
                                                 DEBUGALTLINK, comp_dir_substitutions, output_comp_dir_substitutions,
                                                 nullptr, nullptr, &dwos, &external_debug_info,
                                                 original_had_source_files, dir_exists_cache);
    }

    if (dwos.size() > dwo_count) {
      /* If there are any dwos, check for a dwp. */
      string dwp_candidate = pair.second + ".dwp";
      struct stat statbuf;
      int ret = stat(dwp_candidate.c_str(), &statbuf);
      if (ret == 0 && S_ISREG(statbuf.st_mode)) {
        string build_id = reader.read_buildid();
        if (!build_id.empty()) {
          external_debug_info.insert({ dwp_candidate, build_id, string(DWP) });
        } else {
          LOG(warn) << "Main ELF binary has no build ID!";
        }
      }
    }

    if (has_source_files) {
      relevant_binary_names.push_back(std::move(trace_relative_name));
    } else {
      LOG(info) << "No debuginfo found";
    }
  }

  set<string> resolved_file_names;
  vector<Symlink> symlinks;
  set<string> vcs_dirs;
  build_symlink_map(file_names, &resolved_file_names, &symlinks, &vcs_dirs);
  file_names.clear();

  map<string, vector<const string*>> vcs_files;
  const string empty_string;
  vector<const string*> vcs_stack;
  vector<const string*> vcs_dirs_vector;
  auto vcs_dir_iterator = vcs_dirs.begin();
  bool pushed_empty_string = false;
  for (auto& f : resolved_file_names) {
    while (!vcs_stack.empty() && !starts_with(f, *vcs_stack.back())) {
      vcs_stack.pop_back();
    }
    while (vcs_dir_iterator != vcs_dirs.end()) {
      if (starts_with(f, *vcs_dir_iterator)) {
        vcs_stack.push_back(&*vcs_dir_iterator);
        vcs_dirs_vector.push_back(&*vcs_dir_iterator);
        ++vcs_dir_iterator;
        continue;
      }
      if (*vcs_dir_iterator < f) {
        // Skip this VCS dir because all of its files must have been
        // skipped (not found).
        ++vcs_dir_iterator;
        continue;
      }
      break;
    }
    if (vcs_stack.empty()) {
      if (!pushed_empty_string) {
        pushed_empty_string = true;
        vcs_dirs_vector.push_back(&empty_string);
      }
      vcs_files[empty_string].push_back(&f);
    } else {
      vcs_files[*vcs_stack.back()].push_back(&f);
    }
  }

  printf("{\n");
  printf("  \"relevant_binaries\":[\n");
  for (size_t i = 0; i < relevant_binary_names.size(); ++i) {
    printf("    \"%s\"%s\n", json_escape(relevant_binary_names[i]).c_str(),
           i == relevant_binary_names.size() - 1 ? "" : ",");
  }
  printf("  ],\n");

  printf("  \"loaded_elf_binaries\": [\n");
  for (auto it = original_loaded_elf_names.begin(); it != original_loaded_elf_names.end(); ++it) {
    printf("    \"%s\"%s\n",
      json_escape(*it).c_str(),
      std::next(it) == original_loaded_elf_names.end() ? "" : ",");
  }
  printf("  ],\n");

  printf("  \"comp_dir_substitutions\":{\n");
  for (size_t i = 0; i < output_comp_dir_substitutions.size(); ++i) {
    auto& sub = output_comp_dir_substitutions[i];
    printf("    \"%s\": \"%s\"%s\n", json_escape(sub.trace_relative_name).c_str(),
           json_escape(sub.substitution).c_str(),
           i == output_comp_dir_substitutions.size() - 1 ? "" : ",");
  }
  printf("  },\n");
  printf("  \"external_debug_info\":[\n");
  size_t index = 0;
  for (auto& ext : external_debug_info) {
    printf("    { \"path\":\"%s\", \"build_id\":\"%s\", \"type\":\"%s\" }%s\n",
           json_escape(ext.path).c_str(),
           json_escape(ext.build_id).c_str(),
           json_escape(ext.type).c_str(),
           index == external_debug_info.size() - 1 ? "" : ",");
    ++index;
  }
  printf("  ],\n");
  printf("  \"dwos\":[\n");
  index = 0;
  for (auto& d : dwos) {
    printf("    { \"name\":\"%s\", \"full_path\":\"%s\", \"build_id\":\"%s\", \"trace_file\":\"%s\", ",
           json_escape(d.name).c_str(),
           json_escape(d.full_path).c_str(),
           json_escape(d.build_id).c_str(),
           json_escape(d.trace_file).c_str());
    if (!d.comp_dir.empty()) {
      printf("\"comp_dir\":\"%s\", ", json_escape(d.comp_dir).c_str());
    }
    printf("\"id\":%llu }%s\n",
           (unsigned long long)d.id,
           index == dwos.size() - 1 ? "" : ",");
    ++index;
  }
  printf("  ],\n");
  printf("  \"symlinks\":[\n");
  for (size_t i = 0; i < symlinks.size(); ++i) {
    auto& link = symlinks[i];
    printf("    { \"from\":\"%s\", \"to\":\"%s\" }%s\n",
           json_escape(link.from).c_str(),
           json_escape(link.to).c_str(),
           i == symlinks.size() - 1 ? "" : ",");
  }
  printf("  ],\n");
  printf("  \"files\":{\n");
  for (size_t i = 0; i < vcs_dirs_vector.size(); ++i) {
    auto& dir = *vcs_dirs_vector[i];
    string path = json_escape(dir);
    if (path.size() > 1) {
      // Pop final '/'
      path.pop_back();
    }
    printf("    \"%s\": [\n", path.c_str());
    auto& files = vcs_files[dir];
    for (size_t j = 0; j < files.size(); ++j) {
      printf("      \"%s\"%s\n", json_escape(*files[j], dir.size()).c_str(),
             j == files.size() - 1 ? "" : ",");
    }
    printf("    ]%s\n", i == vcs_dirs_vector.size() - 1 ? "" : ",");
  }
  printf("  }\n");
  printf("}\n");

  return 0;
}

static bool parse_sources_option(vector<string>& args, SourcesFlags& flags) {
  if (parse_global_option(args)) {
    return true;
  }

  static const OptionSpec options[] = {
    { 0, "substitute", HAS_PARAMETER },
    { 1, "gdb-script", HAS_PARAMETER }
  };

  ParsedOption opt;
  if (!Command::parse_option(args, options, &opt)) {
    return false;
  }

  switch (opt.short_name) {
    case 0: {
      auto pos = opt.value.find_first_of('=');
      if (pos != string::npos) {
        auto k = opt.value.substr(0, pos);
        auto v = opt.value.substr(pos+1);
        flags.comp_dir_substitutions.insert(std::pair<string, string>(k, v));
      }
      break;
    }
    case 1: {
      flags.gdb_script = opt.value;
      break;
    }
  }

  return true;
}

int SourcesCommand::run(vector<string>& args) {
  // Various "cannot replay safely..." warnings cannot affect us since
  // we only replay to the first execve.
  Flags::get_for_init().suppress_environment_warnings = true;

  SourcesFlags flags;
  while (parse_sources_option(args, flags)) {
  }

  // (Trace file name, original file name) pairs
  string trace_dir;
  if (!parse_optional_trace_dir(args, &trace_dir)) {
    print_help(stderr);
    return 1;
  }

  TraceReader trace(trace_dir);
  DIR* files = opendir(trace.dir().c_str());
  if (!files) {
    FATAL() << "Can't open trace dir";
  }
  closedir(files);

  map<string, string> binary_file_names;
  while (true) {
    TraceReader::MappedData data;
    bool found;
    KernelMapping km = trace.read_mapped_region(
        &data, &found, TraceReader::VALIDATE, TraceReader::ANY_TIME);
    if (!found) {
      break;
    }
    if (data.source == TraceReader::SOURCE_FILE) {
      binary_file_names.insert(make_pair(std::move(data.file_name), km.fsname()));
    }
  }

  string program;
  {
    ReplaySession::Flags flags;
    flags.redirect_stdio = false;
    flags.share_private_mappings = false;
    flags.replay_stops_at_first_execve = true;
    flags.cpu_unbound = true;

    ReplaySession::shr_ptr replay_session = ReplaySession::create(trace_dir, flags);
    while (true) {
      auto result = replay_session->replay_step(RUN_CONTINUE);
      if (replay_session->done_initial_exec()) {
        program = replay_session->vms()[0]->exe_image();
        break;
      }

      if (result.status == REPLAY_EXITED) {
        break;
      }
    }
  }

  std::vector<std::pair<string, string>> binary_file_names_ordered;
  auto i = binary_file_names.find(program);
  if (i != binary_file_names.end()) {
    binary_file_names_ordered.push_back(*i);
    binary_file_names.erase(program);
  }
  std::copy(binary_file_names.begin(), binary_file_names.end(), std::back_inserter(binary_file_names_ordered));
  auto debug_dirs = make_unique<DebugDirManager>(program, flags.gdb_script);
  return sources(binary_file_names_ordered, flags.comp_dir_substitutions, debug_dirs, false);
}

int ExplicitSourcesCommand::run(vector<string>& args) {
  // Various "cannot replay safely..." warnings cannot affect us since
  // we only replay to the first execve.
  Flags::get_for_init().suppress_environment_warnings = true;

  SourcesFlags flags;
  while (parse_sources_option(args, flags)) {
  }

  // (Trace file name, original file name) pairs
  map<string, string> binary_file_names;
  for (auto arg : args) {
    struct stat statbuf;
    int ret = stat(arg.c_str(), &statbuf);
    if (ret < 0) {
      FATAL() << "Failed to stat `" << arg << "`";
    }
    if (!S_ISREG(statbuf.st_mode)) {
      continue;
    }

    ScopedFd fd = ScopedFd(arg.c_str(), O_RDONLY, 0);
    if (!fd.is_open()) {
      LOG(error) << "Failed to open `" << arg << "`";
      return 1;
    }

    ElfFileReader reader(fd);
    auto buildid = reader.read_buildid();
    if (buildid.empty()) {
      LOG(warn) << "No build-id for `" << arg << "`";
      continue;
    }
    binary_file_names.insert(make_pair(std::move(buildid), arg));
  }

  unique_ptr<DebugDirManager> debug_dirs;
  return sources(binary_file_names, flags.comp_dir_substitutions, debug_dirs, true);
}

} // namespace rr
