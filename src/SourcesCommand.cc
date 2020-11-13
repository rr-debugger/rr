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

/// Prints JSON containing
/// "relevant_binaries": an array of strings, trace-relative binary file names.
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
    "                             for all compilation units.\n");

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
    "                             for all compilation units.\n");

static void parent_dir(string& s) {
  size_t p = s.rfind('/');
  if (p == string::npos) {
    s.clear();
  } else if (p > 0) {
    s.resize(p);
  }
}

static void base_name(string& s) {
  size_t p = s.rfind('/');
  if (p != string::npos) {
    s.erase(0, p + 1);
  }
}

// file_name cannot be null, but the others can be.
static void resolve_file_name(const char* original_file_dir,
                              const char* comp_dir, const char* rel_dir,
                              const char* file_name, set<string>* file_names) {
  const char* names[] = { original_file_dir, comp_dir, rel_dir, file_name };
  ssize_t first_absolute = -1;
  for (ssize_t i = 0; i < 4; ++i) {
    if (names[i] && names[i][0] == '/') {
      first_absolute = i;
    }
  }
  string s = first_absolute >= 0 ? "" : "/";
  for (size_t i = (first_absolute >= 0 ? first_absolute : 0); i < 4; ++i) {
    if (!names[i]) {
      continue;
    }
    if (!s.empty() && s.back() != '/') {
      s.push_back('/');
    }
    s += names[i];
  }
  file_names->insert(move(s));
}

struct DwoInfo {
  string name;
  string trace_file;
  // Could be an empty string
  string comp_dir;
  uint64_t id;
};

static bool process_compilation_units(ElfFileReader& reader,
                                      const string& trace_relative_name,
                                      const string& original_file_name,
                                      const string& comp_dir_substitution,
                                      set<string>* file_names, vector<DwoInfo>* dwos) {
  DwarfSpan debug_info = reader.dwarf_section(".debug_info");
  DwarfSpan debug_abbrev = reader.dwarf_section(".debug_abbrev");
  DwarfSpan debug_str = reader.dwarf_section(".debug_str");
  DwarfSpan debug_str_offsets = reader.dwarf_section(".debug_str_offsets");
  DwarfSpan debug_line = reader.dwarf_section(".debug_line");
  DwarfSpan debug_line_str = reader.dwarf_section(".debug_line_str");
  if (debug_info.empty() || debug_abbrev.empty() ||
      debug_str.empty() || debug_line.empty())  {
    return false;
  }

  DebugStrSpans debug_strs = {
    debug_str,
    debug_str_offsets,
    debug_line_str,
  };

  string original_file_dir = original_file_name;
  parent_dir(original_file_dir);

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
    const char* comp_dir;
    if (!comp_dir_substitution.empty()) {
      comp_dir = comp_dir_substitution.c_str();
    } else {
      comp_dir = cu.die().string_attr(cu, DW_AT_comp_dir, debug_strs, &ok);
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
        string c;
        if (comp_dir) {
          c = comp_dir;
        }
        dwos->push_back({ dwo_name, trace_relative_name, move(c), dwo_id });
      } else {
        LOG(warn) << "DW_AT_GNU_dwo_name but not DW_AT_GNU_dwo_id";
      }
    }
    const char* source_file_name = cu.die().string_attr(cu, DW_AT_name, debug_strs, &ok);
    if (!ok) {
      continue;
    }
    if (source_file_name) {
      resolve_file_name(original_file_dir.c_str(), comp_dir, nullptr, source_file_name, file_names);
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
      resolve_file_name(original_file_dir.c_str(), comp_dir, dir, f.file_name, file_names);
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
    if (path == other.path) {
      return false;
    }
    if (build_id < other.build_id) {
      return true;
    }
    if (build_id == other.build_id) {
      return false;
    }
    return type < other.type;
  }
};

static bool try_auxiliary_file(ElfFileReader& trace_file_reader,
                               const string& trace_relative_name,
                               const string& original_file_name,
                               set<string>* file_names, const string& aux_file_name,
                               const char* file_type,
                               vector<DwoInfo>* dwos,
                               set<ExternalDebugInfo>* external_debug_info) {
  if (aux_file_name.empty()) {
    return false;
  }
  string full_file_name;
  if (aux_file_name.c_str()[0] == '/') {
    full_file_name = aux_file_name;
  } else {
    string original_file_dir = original_file_name;
    parent_dir(original_file_dir);
    full_file_name = original_file_dir + "/" + aux_file_name;
    normalize_file_name(full_file_name);
  }

  ScopedFd fd(full_file_name.c_str(), O_RDONLY);
  if (!fd.is_open()) {
    LOG(warn) << "Can't find external debuginfo file " << full_file_name;
    return false;
  }
  LOG(info) << "Examining external " << full_file_name;
  ElfFileReader reader(fd);
  if (!reader.ok()) {
    LOG(warn) << "Not an ELF file!";
    return false;
  }
  string build_id = trace_file_reader.read_buildid();
  if (build_id.empty()) {
    LOG(warn) << "Main ELF binary has no build ID!";
    return false;
  }
  if (!process_compilation_units(reader, trace_relative_name, original_file_name, {}, file_names, dwos)) {
    LOG(warn) << "No debuginfo!";
    return false;
  }
  external_debug_info->insert({ full_file_name, build_id, string(file_type) });
  return true;
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
        parent_dir(target);
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

static int sources(const map<string, string>& binary_file_names, const map<string, string>& comp_dir_substitutions, bool is_explicit) {
  vector<string> relevant_binary_names;
  set<string> file_names;
  set<ExternalDebugInfo> external_debug_info;
  vector<DwoInfo> dwos;
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
    bool has_source_files;
    LOG(debug) << "Looking for comp_dir substitutions for " << original_name;
    auto it = comp_dir_substitutions.find(original_name);
    if (it != comp_dir_substitutions.end()) {
      LOG(debug) << "\tFound comp_dir substitution " << it->second;
      has_source_files = process_compilation_units(reader, trace_relative_name, pair.second, it->second, &file_names, &dwos);
    } else {
      LOG(debug) << "\tNone found";
      has_source_files = process_compilation_units(reader, trace_relative_name, pair.second, {}, &file_names, &dwos);
    }

    Debuglink debuglink = reader.read_debuglink();
    has_source_files |= try_auxiliary_file(reader, trace_relative_name, pair.second,
      &file_names, debuglink.file_name, "debuglink", &dwos, &external_debug_info);

    Debugaltlink debugaltlink = reader.read_debugaltlink();
    has_source_files |= try_auxiliary_file(reader, trace_relative_name, pair.second,
      &file_names, debugaltlink.file_name, "debugaltlink", &dwos, &external_debug_info);

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
    while (vcs_dir_iterator != vcs_dirs.end() && starts_with(f, *vcs_dir_iterator)) {
      vcs_stack.push_back(&*vcs_dir_iterator);
      vcs_dirs_vector.push_back(&*vcs_dir_iterator);
      ++vcs_dir_iterator;
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
    printf("    { \"name\":\"%s\", \"trace_file\":\"%s\", ",
           json_escape(d.name).c_str(),
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
