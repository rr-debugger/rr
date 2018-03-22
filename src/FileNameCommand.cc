/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include <unordered_set>

#include "AddressSpace.h"
#include "Command.h"
#include "TraceStream.h"
#include "core.h"
#include "main.h"
#include "util.h"

using namespace std;

namespace rr {

class FileNameCommand : public Command {
public:
  virtual int run(vector<string>& args) override;

protected:
  FileNameCommand(const char* name, const char* help) : Command(name, help) {}
  bool parse_file_name(vector<string>& args, string* out);

  static FileNameCommand singleton;
};

FileNameCommand FileNameCommand::singleton(
    "filename",
    " rr filename <trace_file_name>\n"
    "  Prints the original filename for a given trace file name.\n");

static void print_original_file_name(const string& trace_dir,
                                     const string& file_name, FILE* out) {
  TraceReader trace(trace_dir);
  unordered_set<string> original_files;
  string full_file_name = trace.dir() + "/" + file_name;
  while (true) {
    TraceReader::MappedData data;
    bool found;
    KernelMapping km = trace.read_mapped_region(
        &data, &found, TraceReader::VALIDATE, TraceReader::ANY_TIME);
    if (!found) {
      break;
    }
    if (data.source == TraceReader::SOURCE_FILE &&
        data.file_name == full_file_name && !km.fsname().empty() &&
        original_files.find(km.fsname()) == original_files.end()) {
      fprintf(out, "%s\n", km.fsname().c_str());
      original_files.insert(km.fsname());
    }
  }
}

bool FileNameCommand::parse_file_name(vector<string>& args, string* out) {
  if (args.empty() || !verify_not_option(args)) {
    return false;
  }
  *out = args[0];
  args.erase(args.begin());
  return true;
}

int FileNameCommand::run(vector<string>& args) {
  string file_name;
  if (!parse_file_name(args, &file_name) || !args.empty()) {
    print_help(stderr);
    return 1;
  }

  string trace_dir;
  size_t last_slash = file_name.rfind('/');
  if (last_slash == string::npos) {
    trace_dir = ".";
  } else {
    trace_dir = file_name.substr(0, last_slash);
    file_name = file_name.substr(last_slash + 1);
  }
  print_original_file_name(trace_dir, file_name, stdout);
  return 0;
}

} // namespace rr
