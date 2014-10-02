/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

//#define DEBUGTAG "EmuFs"

#include "EmuFs.h"

#include <syscall.h>

#include <fstream>
#include <sstream>
#include <string>

#include "log.h"
#include "ReplaySession.h"

using namespace std;

static void replace_char(string& s, char c, char replacement) {
  size_t i;
  while (string::npos != (i = s.find(c))) {
    s[i] = replacement;
  }
}

EmuFile::~EmuFile() {
  LOG(debug) << "    EmuFs::~File(einode:" << est.st_ino << ")";
}

EmuFile::shr_ptr EmuFile::clone() {
  auto f = EmuFile::create(orig_path.c_str(), est);
  // NB: this isn't the most efficient possible file copy, but
  // it's simple and not too slow.
  ifstream src(proc_path(), ifstream::binary);
  ofstream dst(f->proc_path(), ofstream::binary);
  dst << src.rdbuf();
  return f;
}

string EmuFile::proc_path() const {
  stringstream ss;
  ss << "/proc/" << getpid() << "/fd/" << fd();
  return ss.str();
}

void EmuFile::update(const struct stat& st) {
  assert(est.st_dev == st.st_dev && est.st_ino == st.st_ino);
  if (est.st_size != st.st_size) {
    resize_shmem_segment(file, st.st_size);
  }
  est = st;
}

/*static*/ EmuFile::shr_ptr EmuFile::create(const char* orig_path,
                                            const struct stat& est) {
  // Sanitize the mapped file path so that we can use it in a
  // leaf name.
  string path_tag(orig_path);
  replace_char(path_tag, '/', '\\');

  stringstream name;
  name << "rr-emufs-" << getpid() << "-dev-" << est.st_dev << "-inode-"
       << est.st_ino << "-" << path_tag;
  shr_ptr f(new EmuFile(create_shmem_segment(name.str().c_str(), est.st_size),
                        est, orig_path));
  LOG(debug) << "created emulated file for " << orig_path << " as "
             << name.str();
  return f;
}

EmuFile::EmuFile(ScopedFd&& fd, const struct stat& est, const char* orig_path)
    : est(est), orig_path(orig_path), file(std::move(fd)), is_marked(false) {}

EmuFile::shr_ptr EmuFs::at(const FileId& id) const { return files.at(id); }

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

    mark_used_vfiles(t, *as, &nr_marked_files);
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
    LOG(debug) << "  emufs gc reclaiming einode:" << it->disp_inode()
               << "; fs name `" << files[*it]->emu_path() << "'";
    files.erase(*it);
  }
}

EmuFile::shr_ptr EmuFs::get_or_create(const TraceMappedRegion& mf) {
  FileId id(mf.stat(), PSEUDODEVICE_SHARED_MMAP_FILE);
  auto it = files.find(id);
  if (it != files.end()) {
    it->second->update(mf.stat());
    return it->second;
  }
  auto vf = EmuFile::create(mf.file_name().c_str(), mf.stat());
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

void EmuFs::mark_used_vfiles(Task* t, const AddressSpace& as,
                             size_t* nr_marked_files) {
  for (auto& kv : as.memmap()) {
    const MappableResource& r = kv.second;
    LOG(debug) << "  examining " << r.fsname.c_str() << " ...";

    auto id_ef = files.find(r.id);
    if (id_ef == files.end()) {
      ASSERT(t, !r.is_shared_mmap_file());
      continue;
    }
    auto ef = id_ef->second;
    if (!ef->marked()) {
      ef->mark();
      LOG(debug) << "    marked einode:" << r.id.disp_inode();
      ++*nr_marked_files;
      if (files.size() == *nr_marked_files) {
        LOG(debug) << "  (marked all files, bailing)";
        return;
      }
    }
  }
}

EmuFs::AutoGc::AutoGc(ReplaySession& session, int syscallno,
                      SyscallEntryOrExit state)
    : session(session),
      is_gc_point(session.emufs().size() > 0 && SYSCALL_EXIT == state &&
                  (SYS_close == syscallno || SYS_munmap == syscallno)) {
  if (is_gc_point) {
    assert(SYS_close == syscallno || SYS_munmap == syscallno);
    LOG(debug) << "emufs gc required because of syscall `"
               << (SYS_close == syscallno ? "close" : "munmap") << "'";
  }
}

EmuFs::AutoGc::~AutoGc() {
  if (is_gc_point) {
    session.gc_emufs();
  }
}
