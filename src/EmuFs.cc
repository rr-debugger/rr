/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "EmuFs.h"

#include <syscall.h>

#include <fstream>
#include <sstream>
#include <string>

#include "AddressSpace.h"
#include "ReplaySession.h"
#include "core.h"
#include "kernel_abi.h"
#include "kernel_metadata.h"
#include "log.h"

using namespace std;

namespace rr {

static void replace_char(string& s, char c, char replacement) {
  size_t i;
  while (string::npos != (i = s.find(c))) {
    s[i] = replacement;
  }
}

EmuFile::~EmuFile() {
  LOG(debug) << "    EmuFs::~File(einode:" << inode_ << ")";
  owner.destroyed_file(*this);
}

EmuFile::shr_ptr EmuFile::clone(EmuFs& owner) {
  auto f = EmuFile::create(owner, orig_path.c_str(), device(), inode(), size_);

  uint64_t data[65536 / sizeof(uint64_t)];
  uint64_t offset = 0;
  while (offset < size_) {
    ssize_t amount = min<uint64_t>(size_ - offset, sizeof(data));
    ssize_t ret = pread64(fd(), data, amount, offset);
    if (ret <= 0) {
      FATAL() << "Couldn't read all the data";
    }
    // There could have been a short read
    amount = ret;
    uint8_t* data_ptr = reinterpret_cast<uint8_t*>(data);
    while (amount > 0) {
      ret = pwrite64(f->fd(), data_ptr, amount, offset);
      if (ret <= 0) {
        FATAL() << "Couldn't write all the data";
      }
      amount -= ret;
      data_ptr += ret;
      offset += ret;
    }
  }

  return f;
}

string EmuFile::proc_path() const {
  stringstream ss;
  ss << "/proc/" << getpid() << "/fd/" << fd().get();
  return ss.str();
}

void EmuFile::update(dev_t device, ino_t inode, uint64_t size) {
  DEBUG_ASSERT(device_ == device && inode_ == inode);
  ensure_size(size);
}

void EmuFile::ensure_size(uint64_t size) {
  if (size_ < size) {
    resize_shmem_segment(file, size);
    size_ = size;
  }
}

/*static*/ EmuFile::shr_ptr EmuFile::create(EmuFs& owner,
                                            const string& orig_path,
                                            dev_t orig_device, ino_t orig_inode,
                                            uint64_t orig_file_size) {
  // Sanitize the mapped file path so that we can use it in a
  // leaf name.
  string path_tag(orig_path);
  replace_char(path_tag, '/', '\\');

  stringstream name;
  name << tmp_dir() << "/rr-emufs-" << getpid() << "-dev-" << orig_device
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

  shr_ptr f(new EmuFile(owner, std::move(fd), orig_path, real_name, orig_device,
                        orig_inode, orig_file_size));

  LOG(debug) << "created emulated file for " << orig_path << " as "
             << name.str();
  return f;
}

EmuFile::EmuFile(EmuFs& owner, ScopedFd&& fd, const string& orig_path,
                 const string& real_path, dev_t orig_device, ino_t orig_inode,
                 uint64_t orig_file_size)
    : orig_path(orig_path),
      tmp_path(real_path),
      file(std::move(fd)),
      owner(owner),
      size_(orig_file_size),
      device_(orig_device),
      inode_(orig_inode) {}

EmuFile::shr_ptr EmuFs::at(const KernelMapping& recorded_map) const {
  return files.at(FileId(recorded_map)).lock();
}

bool EmuFs::has_file_for(const KernelMapping& recorded_map) const {
  return files.find(FileId(recorded_map)) != files.end();
}

EmuFile::shr_ptr EmuFs::clone_file(EmuFile::shr_ptr file) {
  DEBUG_ASSERT(file);
  auto c = file->clone(*this);
  files[FileId(*file)] = c;
  return c;
}

EmuFile::shr_ptr EmuFs::get_or_create(const KernelMapping& recorded_km,
                                      uint64_t file_size) {
  FileId id(recorded_km);
  auto it = files.find(id);
  if (it != files.end()) {
    it->second.lock()->update(recorded_km.device(), recorded_km.inode(),
                              file_size);
    return it->second.lock();
  }
  auto vf = EmuFile::create(*this, recorded_km.fsname(), recorded_km.device(),
                            recorded_km.inode(), file_size);
  files[id] = vf;
  return vf;
}

void EmuFs::log() const {
  LOG(error) << "EmuFs " << this << " with " << files.size() << " files:";
  for (auto& kv : files) {
    auto file = kv.second.lock();
    LOG(error) << "  " << file->emu_path();
  }
}

/*static*/ EmuFs::shr_ptr EmuFs::create() { return shr_ptr(new EmuFs()); }

EmuFs::EmuFs() {}

EmuFs::FileId::FileId(const KernelMapping& recorded_map)
    : device(recorded_map.device()), inode(recorded_map.inode()) {}

} // namespace rr
