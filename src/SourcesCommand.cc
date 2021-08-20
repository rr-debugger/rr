/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include <dirent.h>
#include <unistd.h>

#include <set>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <map>

#include "Command.h"
#include "ElfReader.h"
#include "RecordSession.h"
#include "TraceStream.h"
#include "core.h"
#include "log.h"
#include "main.h"
#include "util.h"

using namespace std;

namespace rr {

const char* DEBUGLINK = "debuglink";
const char* DEBUGALTLINK = "debugaltlink";

/// Prints JSON containing
/// "relevant_binaries": an array of strings, trace-relative binary file names (or build-ids, for explicit-sources).
///   These are ELF files in the trace that our collected data is relevant to.
/// "external_debug_info": an array of objects, {"path":<path>, "build_id":<build-id>, "type":<type>}
///   These are ELF files in the filesystem that contain separate debuginfo. "build-id" is the
///   build-id of the file from whence it originated, as a string. "type" is the type of
///   external file, one of "debuglink", "debugaltlink". Note that for "debugaltlink", it is possible
///   to have the same file appearing multiple times with different build-ids, when it's shared by
///   multiple ELF binaries.
/// "dwo": an array of objects, {"name":<name>, "trace_file":<name>, "comp_dir":<path>, "id":<value>}
///   These are the references to DWO files found in the trace binaries. "name" is the value of
/// DW_AT_GNU_dwo_name. "trace_file" is the trace-relative binary file name. "comp_dir" is the
/// value of DW_AT_comp_dir for the compilation unit containing the DWO reference. "id"
/// is the value of DW_AT_GNU_dwo_id (64 bit number).
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
    "                             e.g. libc-2.32.so\n");

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

static void base_name(string& s) {
  size_t p = s.rfind('/');
  if (p != string::npos) {
    s.erase(0, p + 1);
  }
}

static bool is_absolute(string& s) {
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

// Resolve a file name relative to a compilation directory and relative directory.
// file_name cannot be null, but the others can be.
// Takes into accout the original file name as follows:
// -- if comp_dir, rel_dir or file_name are absolute, or original_file_name is NULL,
// then ignore original_file_name.
// The result is just the result of combining comp_dir/rel_dir/file_name.
// -- otherwise they're all relative to some build directory. We hypothesize
// the build directory is some ancestor directory of original_file_name.
// We try making comp_dir/rel_dir/file_name relative to each ancestor directory
// of original_file_name, and if we find a file there, we return that name.
//
// If non-empty, `comp_dir_substution` should replace `original_comp_dir`
// in `rel_dir` if `original_comp_dir` is a prefix of `rel_dir`.
static string resolve_file_name(const char* original_file_name,
                                const char* comp_dir,
                                const char* original_comp_dir,
                                const string& comp_dir_substitution,
                                const char* rel_dir,
                                const char* file_name,
                                DirExistsCache& dir_exists_cache) {
  string path = file_name;
  if (is_absolute(path)) {
    return path;
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
      return path;
    }
  }
  if (comp_dir) {
    prepend_path(comp_dir, path);
    if (is_absolute(path)) {
      return path;
    }
  }
  if (!original_file_name) {
    return path;
  }
  string original(original_file_name);
  while (true) {
    dir_name(original);
    if (original.empty()) {
      return path;
    }
    string candidate = original + "/" + path;
    if (dir_exists_cache.dir_exists(candidate)) {
      return candidate;
    }
  }
}

struct DwoInfo {
  string name;
  string trace_file;
  // Could be an empty string
  string comp_dir;
  string full_path;
  uint64_t id;
};

static bool process_compilation_units(ElfFileReader& reader,
                                      ElfFileReader* sup_reader,
                                      const string& trace_relative_name,
                                      const string& original_file_name,
                                      const string& comp_dir_substitution,
                                      set<string>* file_names, vector<DwoInfo>* dwos,
                                      DirExistsCache& dir_exists_cache) {
  DwarfSpan debug_info = reader.dwarf_section(".debug_info");
  DwarfSpan debug_abbrev = reader.dwarf_section(".debug_abbrev");
  DwarfSpan debug_str = reader.dwarf_section(".debug_str");
  DwarfSpan debug_str_sup = sup_reader ? sup_reader->dwarf_section(".debug_str") : DwarfSpan();
  DwarfSpan debug_str_offsets = reader.dwarf_section(".debug_str_offsets");
  DwarfSpan debug_line = reader.dwarf_section(".debug_line");
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
    const char* original_comp_dir = cu.die().string_attr(cu, DW_AT_comp_dir, debug_strs, &ok);;
    const char* comp_dir;
    if (!comp_dir_substitution.empty()) {
      comp_dir = comp_dir_substitution.c_str();
    } else {
      comp_dir = original_comp_dir;
      if (!ok) {
        continue;
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
          continue;
        }
      }
      if (has_dwo_id) {
        string full_name = resolve_file_name(original_file_name.c_str(), comp_dir, original_comp_dir, comp_dir_substitution, nullptr, dwo_name, dir_exists_cache);
        string c;
        if (comp_dir) {
          c = comp_dir;
        }
        dwos->push_back({ dwo_name, trace_relative_name, move(c), full_name, dwo_id });
      } else {
        LOG(warn) << "DW_AT_GNU_dwo_name but not DW_AT_GNU_dwo_id";
      }
    }
    const char* source_file_name = cu.die().string_attr(cu, DW_AT_name, debug_strs, &ok);
    if (!ok) {
      continue;
    }
    if (source_file_name) {
      file_names->insert(resolve_file_name(original_file_name.c_str(), comp_dir, original_comp_dir, comp_dir_substitution, nullptr, source_file_name, dir_exists_cache));
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
      file_names->insert(resolve_file_name(original_file_name.c_str(), comp_dir, original_comp_dir, comp_dir_substitution, dir, f.file_name, dir_exists_cache));
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
                    string& full_file_name) {
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

    // If none of those worked, give up.
    LOG(warn) << "Exhausted auxilliary debuginfo search locations for " << aux_file_name;
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
find_auxiliary_file_by_buildid(ElfFileReader& trace_file_reader, string& full_file_name) {
  string build_id = trace_file_reader.read_buildid();
  if (build_id.empty()) {
    LOG(warn) << "Main ELF binary has no build ID!";
    return nullptr;
  }
  if (build_id.size() < 3) {
    LOG(warn) << "Build ID is too short!";
    return nullptr;
  }

  string path = "/usr/lib/debug/.build-id/" + build_id.substr(0, 2) + "/" + build_id.substr(2) + ".debug";
  ScopedFd fd(path.c_str(), O_RDONLY);
  if (!fd.is_open()) {
    LOG(info) << "Can't find external debuginfo file " << path;
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
                                   const map<string, string>& comp_dir_substitutions,
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
                                         it->second, file_names, dwos, dir_exists_cache);
  } else {
    LOG(debug) << "\tNo comp_dir substitution found";
    did_work = process_compilation_units(aux_file_reader, alt_file_reader,
                                         trace_relative_name, original_file_name,
                                         {}, file_names, dwos, dir_exists_cache);
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
                               const map<string, string>& comp_dir_substitutions,
                               vector<DwoInfo>* dwos,
                               set<ExternalDebugInfo>* external_debug_info,
                               DirExistsCache& dir_exists_cache) {
  string full_file_name;
  auto reader = find_auxiliary_file(original_file_name, aux_file_name,
                                    full_file_name);
  if (!reader) {
    reader = find_auxiliary_file_by_buildid(trace_file_reader, full_file_name);
    if (!reader) {
      return false;
    }
  }

  /* A debuglink file can have its own debugaltlink */
  string full_altfile_name;
  Debugaltlink debugaltlink = reader->read_debugaltlink();
  auto altlink_reader = find_auxiliary_file(original_file_name, debugaltlink.file_name,
                                            full_altfile_name);

  bool has_source_files = process_auxiliary_file(trace_file_reader, *reader, altlink_reader.get(),
                                                 trace_relative_name, original_file_name,
                                                 file_names, full_file_name, DEBUGLINK,
                                                 comp_dir_substitutions,
                                                 dwos, external_debug_info, false, dir_exists_cache);

  if (altlink_reader) {
    has_source_files |= process_auxiliary_file(trace_file_reader, *altlink_reader, nullptr,
                                               trace_relative_name, original_file_name,
                                               file_names, full_altfile_name, DEBUGALTLINK,
                                               comp_dir_substitutions,
                                               dwos, external_debug_info, has_source_files, dir_exists_cache);
  }
  return has_source_files;
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

static void check_vcs_root(string& path, set<string>* vcs_dirs) {
  if (has_subdir(path, "/.git") || has_subdir(path, "/.hg")) {
    vcs_dirs->insert(path + "/");
  }
}

// Returns an empty string if the path does not exist or
// is not accessible.
// `path` need not be normalized, i.e. may contain .. or .
// components.
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
        resolved_dirs->insert(make_pair(move(resolved_base), resolved));
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

struct OutputCompDirSubstitution {
  string trace_relative_name;
  string substitution;
};

static int sources(const map<string, string>& binary_file_names, const map<string, string>& comp_dir_substitutions, bool is_explicit) {
  vector<string> relevant_binary_names;
  set<string> file_names;
  set<ExternalDebugInfo> external_debug_info;
  vector<DwoInfo> dwos;
  vector<OutputCompDirSubstitution> output_comp_dir_substitutions;
  DirExistsCache dir_exists_cache;
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
    base_name(original_name);
    Debugaltlink debugaltlink = reader.read_debugaltlink();

    string full_altfile_name;
    auto altlink_reader = find_auxiliary_file(pair.second, debugaltlink.file_name,
                                              full_altfile_name);

    bool has_source_files;
    LOG(debug) << "Looking for comp_dir substitutions for " << original_name;
    auto it = comp_dir_substitutions.find(original_name);
    if (it != comp_dir_substitutions.end()) {
      LOG(debug) << "\tFound comp_dir substitution " << it->second;
      output_comp_dir_substitutions.push_back({ trace_relative_name, it->second });
      has_source_files = process_compilation_units(reader, altlink_reader.get(),
                                                   trace_relative_name, pair.second,
                                                   it->second, &file_names, &dwos, dir_exists_cache);
    } else {
      LOG(debug) << "\tNo comp_dir substitution found";
      has_source_files = process_compilation_units(reader, altlink_reader.get(),
                                                   trace_relative_name, pair.second,
                                                   {}, &file_names, &dwos, dir_exists_cache);
    }
    /* If the original binary had source files, force the inclusion of any debugaltlink
     * file, even if it does not itself have compilation units (it may have relevant strings)
     */
    const bool original_had_source_files = has_source_files;

    Debuglink debuglink = reader.read_debuglink();
    has_source_files |= try_debuglink_file(reader, trace_relative_name, pair.second,
                                           &file_names, debuglink.file_name,
                                           comp_dir_substitutions, &dwos,
                                           &external_debug_info, dir_exists_cache);

    if (altlink_reader) {
      has_source_files |= process_auxiliary_file(reader, *altlink_reader, nullptr,
                                                 trace_relative_name, pair.second,
                                                 &file_names, full_altfile_name,
                                                 DEBUGALTLINK, comp_dir_substitutions,
                                                 &dwos, &external_debug_info,
                                                 original_had_source_files, dir_exists_cache);
    }

    if (has_source_files) {
      relevant_binary_names.push_back(move(trace_relative_name));
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
    printf("    { \"name\":\"%s\", \"full_path\":\"%s\", \"trace_file\":\"%s\", ",
           json_escape(d.name).c_str(),
           json_escape(d.full_path).c_str(),
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

static bool parse_sources_option(vector<string>& args, map<string, string>& comp_dir_substitutions) {
  if (parse_global_option(args)) {
    return true;
  }

  static const OptionSpec options[] = {
    { 0, "substitute", HAS_PARAMETER }
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
        comp_dir_substitutions.insert(std::pair<string, string>(k, v));
      }
      break;
    }
  }

  return true;
}

int SourcesCommand::run(vector<string>& args) {
  map<string, string> comp_dir_substitutions;
  while (parse_sources_option(args, comp_dir_substitutions)) {
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
      binary_file_names.insert(make_pair(move(data.file_name), km.fsname()));
    }
  }

  return sources(binary_file_names, comp_dir_substitutions, false);
}

int ExplicitSourcesCommand::run(vector<string>& args) {
  map<string, string> comp_dir_substitutions;
  while (parse_sources_option(args, comp_dir_substitutions)) {
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
    binary_file_names.insert(make_pair(move(buildid), arg));
  }

  return sources(binary_file_names, comp_dir_substitutions, true);
}

} // namespace rr
