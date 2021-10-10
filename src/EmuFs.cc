/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "EmuFs.h"

#include <syscall.h>
#include <sys/mman.h>

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

EmuFile::~EmuFile() {
  LOG(debug) << "    EmuFs::~File(einode:" << inode_ << ")";
  owner.destroyed_file(*this);
}

EmuFile::shr_ptr EmuFile::clone(EmuFs& owner) {
  auto f = EmuFile::create(owner, orig_path.c_str(), device(), inode(), size_);

  // We could try using FICLONE but tmpfs doesn't support that yet so let's just
  // not bother for now.

  // Avoid copying holes.
  vector<uint8_t> buf;
  uint64_t offset = 0;
  while (offset < size_) {
    ssize_t ret = lseek(fd(), offset, SEEK_HOLE);
    if (ret < 0) {
      ret = size_;
    } else {
      if (uint64_t(ret) < offset) {
        FATAL() << "lseek returned hole before requested offset";
      }
    }
    uint64_t hole = ret;
    // Copy data
    while (offset < hole) {
      loff_t off_in = offset;
      loff_t off_out = offset;
      ssize_t ncopied = syscall(NativeArch::copy_file_range, file.get(), &off_in,
                                f->fd().get(), &off_out, hole - offset, 0);
      if (ncopied >= 0) {
        if (ncopied == 0) {
          FATAL() << "Didn't copy anything";
        }
        offset += ncopied;
        continue;
      }

      ssize_t amount = min<uint64_t>(hole - offset, 4*1024*1024);
      buf.resize(amount);
      ret = pread64(fd(), buf.data(), amount, offset);
      if (ret <= 0) {
        FATAL() << "Couldn't read all the data";
      }
      ssize_t written = pwrite_all_fallible(f->fd(), buf.data(), ret, offset);
      if (written < ret) {
        FATAL() << "Couldn't write all the data";
      }
      offset += written;
    }
    if (offset < size_) {
      // Look for the end of the hole, if any
      ret = lseek(fd(), offset, SEEK_DATA);
      if (ret < 0) {
        if (errno != ENXIO) {
          FATAL() << "Couldn't find data";
        }
        break;
      }
      if (uint64_t(ret) <= offset) {
        FATAL() << "Zero sized hole?";
      }
      // Skip the hole
      offset = ret;
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

std::string make_temp_name(const string& orig_path, dev_t orig_device,
                           ino_t orig_inode)
{
  stringstream name;
  name << "rr-emufs-" << getpid() << "-dev-" << orig_device
       << "-inode-" << orig_inode << "-" << orig_path;
  // The linux man page for memfd_create says the length limit for the name
  // argument is 249 bytes, evidently because it prepends "memfd:" to the
  // parameter before using it.
  return name.str().substr(0, 249);
}

/*static*/ EmuFile::shr_ptr EmuFile::create(EmuFs& owner,
                                            const string& orig_path,
                                            dev_t orig_device, ino_t orig_inode,
                                            uint64_t orig_file_size) {
  string real_name = make_temp_name(orig_path, orig_device, orig_inode);
  ScopedFd fd(open_memory_file(real_name));
  if (!fd.is_open()) {
    FATAL() << "Failed to create shmem segment for " << real_name;
  }
  resize_shmem_segment(fd, orig_file_size);

  shr_ptr f(new EmuFile(owner, std::move(fd), orig_path, real_name, orig_device,
                        orig_inode, orig_file_size));

  LOG(debug) << "created emulated file for " << orig_path << " as "
             << real_name;
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

EmuFile::shr_ptr EmuFs::get_or_create(const KernelMapping& recorded_km) {
  FileId id(recorded_km);
  auto it = files.find(id);
  uint64_t min_file_size =
    recorded_km.file_offset_bytes() + recorded_km.size();
  if (it != files.end()) {
    it->second.lock()->update(recorded_km.device(), recorded_km.inode(),
                              min_file_size);
    return it->second.lock();
  }
  auto vf = EmuFile::create(*this, recorded_km.fsname(), recorded_km.device(),
                            recorded_km.inode(), min_file_size);
  files[id] = vf;
  return vf;
}

EmuFile::shr_ptr EmuFs::find(dev_t device, ino_t inode) {
  FileId id(device, inode);
  auto it = files.find(id);
  if (it == files.end()) {
    return EmuFile::shr_ptr();
  }
  return it->second.lock();
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

FileId::FileId(const KernelMapping& recorded_map)
    : device(recorded_map.device()), inode(recorded_map.inode()) {}

FileId::FileId(const EmuFile& emu_file)
    : device(emu_file.device()), inode(emu_file.inode()) {}

} // namespace rr
