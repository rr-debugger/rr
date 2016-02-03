/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

//#define DEBUGTAG "EmuFs"

#include "EmuFs.h"

#include <syscall.h>

#include <fstream>
#include <sstream>
#include <string>

#include "kernel_abi.h"
#include "kernel_metadata.h"
#include "log.h"
#include "ReplaySession.h"

using namespace rr;
using namespace std;

static void replace_char(string& s, char c, char replacement) {
  size_t i;
  while (string::npos != (i = s.find(c))) {
    s[i] = replacement;
  }
}

EmuFile::~EmuFile() {
  LOG(debug) << "    EmuFs::~File(einode:" << inode_ << ")";
}

EmuFile::shr_ptr EmuFile::clone() {
  auto f = EmuFile::create(orig_path.c_str(), device(), inode(), size_);
  // NB: this isn't the most efficient possible file copy, but
  // it's simple and not too slow.
  ifstream src(proc_path(), ifstream::binary);
  ofstream dst(f->proc_path(), ofstream::binary);
  dst << src.rdbuf();
  return f;
}

string EmuFile::proc_path() const {
  stringstream ss;
  ss << "/proc/" << getpid() << "/fd/" << fd().get();
  return ss.str();
}

void EmuFile::update(dev_t device, ino_t inode, uint64_t size) {
  assert(device_ == device && inode_ == inode);
  if (size_ != size) {
    resize_shmem_segment(file, size);
  }
  size_ = size;
}

/*static*/ EmuFile::shr_ptr EmuFile::create(const string& orig_path,
                                            dev_t orig_device, ino_t orig_inode,
                                            uint64_t orig_file_size) {
  // Sanitize the mapped file path so that we can use it in a
  // leaf name.
  string path_tag(orig_path);
  replace_char(path_tag, '/', '\\');

  stringstream name;
  name << SHMEM_FS << "/rr-emufs-" << getpid() << "-dev-" << orig_device
       << "-inode-" << orig_inode << "-" << path_tag;
  string real_name = name.str().substr(0, 255);

  ScopedFd fd =
      open(real_name.c_str(), O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
  if (!fd.is_open()) {
    FATAL() << "Failed to create shmem segment " << real_name;
  }
  /* Remove the fs name so that we don't have to worry about
   * cleaning up this segment in error conditions. */
  unlink(real_name.c_str());
  resize_shmem_segment(fd, orig_file_size);

  shr_ptr f(new EmuFile(std::move(fd), orig_path, real_name, orig_device,
                        orig_inode, orig_file_size));

  LOG(debug) << "created emulated file for " << orig_path << " as "
             << name.str();
  return f;
}

EmuFile::EmuFile(ScopedFd&& fd, const string& orig_path,
                 const string& real_path, dev_t orig_device, ino_t orig_inode,
                 uint64_t orig_file_size)
    : orig_path(orig_path),
      tmp_path(real_path),
      file(std::move(fd)),
      size_(orig_file_size),
      device_(orig_device),
      inode_(orig_inode),
      is_marked(false) {}

EmuFile::shr_ptr EmuFs::at(const KernelMapping& recorded_map) const {
  return files.at(FileId(recorded_map));
}

bool EmuFs::has_file_for(const KernelMapping& recorded_map) const {
  return files.find(FileId(recorded_map)) != files.end();
}

EmuFs::shr_ptr EmuFs::clone() {
  shr_ptr fs(new EmuFs());
  for (auto& kv : files) {
    const FileId& id = kv.first;
    fs->files[id] = kv.second->clone();
  }
  return fs;
}

void EmuFs::gc(const Session& session) {
  // XXX this implementation is unnecessarily slow.  But before
  // throwing it away for something different, give it another
  // shot once rr is caching local mmaps for all address spaces,
  // which obviates the need for the yuck slow maps parsing
  // here.
  LOG(debug) << "Beginning emufs gc of " << files.size() << " files";

  // Mark in-use files by iterating through the mmaps of all
  // tracee address spaces.
  //
  // We inject these maps into the tracee and are careful to
  // close the injected fd after we finish the mmap.  That means
  // that the only way tracees can hold a reference to the
  // underlying inode is through a memory mapping.  So to
  // determine if a file is in use, we only have to find a
  // recognizable filename in some tracee's memory map.
  //
  // We check *all* tracee file tables because tracees can share
  // fds with each other in many ways, and we don't attempt to
  // track any of that.
  //
  // TODO: assuming AddressSpace == FileTable, but technically
  // they're different things: two tracees could share an
  // address space but have different file tables.
  size_t nr_marked_files = 0;
  for (auto& as : session.vms()) {
    Task* t = *as->task_set().begin();
    LOG(debug) << "  iterating /proc/" << t->tid << "/maps ...";

    mark_used_vfiles(*as, &nr_marked_files);
    if (files.size() == nr_marked_files) {
      break;
    }
  }

  // Sweep all the virtual files that weren't marked.  It might
  // be possible that a later task will mmap the same underlying
  // file that we're about to destroy.  That's perfectly fine;
  // we'll just create it anew, and restore its addressible
  // contents from the snapshot saved to the trace.  Since there
  // are no live references to the file in the interim, tracees
  // can't observe the destroy/recreate operation.
  vector<FileId> garbage;
  for (auto it = files.begin(); it != files.end(); ++it) {
    if (!it->second->marked()) {
      garbage.push_back(it->first);
    }
    it->second->unmark();
  }
  for (auto it = garbage.begin(); it != garbage.end(); ++it) {
    LOG(debug) << "  emufs gc reclaiming einode:" << it->inode << "; fs name `"
               << files[*it]->emu_path() << "'";
    files.erase(*it);
  }
}

EmuFile::shr_ptr EmuFs::get_or_create(const KernelMapping& recorded_km,
                                      uint64_t file_size) {
  FileId id(recorded_km);
  auto it = files.find(id);
  if (it != files.end()) {
    it->second->update(recorded_km.device(), recorded_km.inode(), file_size);
    return it->second;
  }
  auto vf = EmuFile::create(recorded_km.fsname(), recorded_km.device(),
                            recorded_km.inode(), file_size);
  files[id] = vf;
  return vf;
}

void EmuFs::log() const {
  LOG(error) << "EmuFs " << this << " with " << files.size() << " files:";
  for (auto& kv : files) {
    auto file = kv.second;
    LOG(error) << "  " << file->emu_path();
  }
}

/*static*/ EmuFs::shr_ptr EmuFs::create() { return shr_ptr(new EmuFs()); }

EmuFs::EmuFs() {}

void EmuFs::mark_used_vfiles(const AddressSpace& as, size_t* nr_marked_files) {
  for (auto m : as.maps()) {
    LOG(debug) << "  examining " << m.map.fsname().c_str() << " ...";

    FileId id(m.recorded_map);
    auto id_ef = files.find(id);
    if (id_ef == files.end()) {
      // Mapping isn't relevant. Not all shared mappings get EmuFs entries
      // (e.g. readonly shared mappings of certain system files, like fonts).
      continue;
    }
    auto ef = id_ef->second;
    if (!ef->marked()) {
      ef->mark();
      LOG(debug) << "    marked einode:" << id.inode;
      ++*nr_marked_files;
      if (files.size() == *nr_marked_files) {
        LOG(debug) << "  (marked all files, bailing)";
        return;
      }
    }
  }
}
