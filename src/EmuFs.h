/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_EMUFS_H_
#define RR_EMUFS_H_

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "ScopedFd.h"

namespace rr {

class AddressSpace;
class EmuFs;
class KernelMapping;
class ReplaySession;
class Session;
class Task;

/**
 * Implement an "emulated file system" consisting of files that were
 * mmap'd shared during recording.  These files require special
 * treatment because (i) they were most likely modified during
 * recording, so (ii) the original file contents only exist as
 * snapshots in the trace, but (iii) all mappings of the file must
 * point at the same underling resource, so that modifications are
 * seen by all mappees.
 *
 * The rr EmuFs creates "emulated files" in shared memory during
 * replay.  Each efile is uniquely identified at a given event in the
 * trace by |(edev, einode)| (i.e., the recorded device ID and inode).
 * "What about inode recycling", you're probably thinking to yourself.
 * This scheme can cope with inode recycling, given a very important
 * assumption discussed below.
 *
 * Why is inode recycling not a problem?  Assume that an mmap'd file
 * F_0 at trace time t_0 has the same (device, inode) ID as a
 * different file F_1 at trace time t_1.  By definition, if the inode
 * ID was recycled in [t_0, t_1), then all references to F_0 must have
 * been dropped in that interval.  A corollary of that is that all
 * memory mappings of F_0 must have been fully unmapped in the
 * interval.  As per the first long comment in |gc()| below, an
 * emulated file can only be "live" during replay if some tracee still
 * has a mapping of it.  Tracees' mappings of emulated files is a
 * subset of the ways they can create references to real files during
 * recording.  Therefore the event during replay that drops the last
 * reference to the emulated F_0 must be a tracee unmapping of F_0.
 *
 * So as long as we GC emulated F_0 at the event of its fatal
 * unmapping, the lifetimes of emulated F_0 and emulated F_1 must be
 * disjoint.  And F_0 being GC'd at that point is the important
 * assumption mentioned above.
 */

/**
 * A file within an EmuFs.  The file is real, but it's mapped to file
 * ID that was recorded during replay.
 */
class EmuFile {
public:
  typedef std::shared_ptr<EmuFile> shr_ptr;

  ~EmuFile();

  /**
   * Return the fd of the real file backing this.
   */
  const ScopedFd& fd() const { return file; }

  /**
   * Return a pathname referring to the fd of this in this
   * tracer's address space.  For example, "/proc/12345/fd/5".
   */
  std::string proc_path() const;

  /**
   * Return the path of the original file from recording, the
   * one this is emulating.
   */
  const std::string emu_path() const { return orig_path; }

  const std::string real_path() const { return tmp_path; }

  dev_t device() const { return device_; }
  ino_t inode() const { return inode_; }

  void ensure_size(uint64_t size);

private:
  friend class EmuFs;

  EmuFile(EmuFs& owner, ScopedFd&& fd, const std::string& orig_path,
          const std::string& real_path, dev_t device, ino_t inode,
          uint64_t file_size);

  /**
   * Return a copy of this file.  See |create()| for the meaning
   * of |fs_tag|.
   */
  shr_ptr clone(EmuFs& owner);

  /**
   * Ensure that the emulated file is sized to match a later
   * stat() of it.
   */
  void update(dev_t device, ino_t inode, uint64_t size);

  /**
   * Create a new emulated file for |orig_path| that will
   * emulate the recorded attributes |est|.  |tag| is used to
   * uniquely identify this file among multiple EmuFs's that
   * might exist concurrently in this tracer process.
   */
  static shr_ptr create(EmuFs& owner, const std::string& orig_path,
                        dev_t orig_device, ino_t orig_inode,
                        uint64_t orig_file_size);

  std::string orig_path;
  std::string tmp_path;
  ScopedFd file;
  EmuFs& owner;
  uint64_t size_;
  dev_t device_;
  ino_t inode_;

  EmuFile(const EmuFile&) = delete;
  EmuFile operator=(const EmuFile&) = delete;
};

class EmuFs {
public:
  typedef std::shared_ptr<EmuFs> shr_ptr;

  /**
   * Return the EmuFile for |recorded_map|, which must exist or this won't
   * return.
   */
  EmuFile::shr_ptr at(const KernelMapping& recorded_map) const;

  bool has_file_for(const KernelMapping& recorded_map) const;

  EmuFile::shr_ptr clone_file(EmuFile::shr_ptr emu_file);

  /**
   * Return an emulated file representing the recorded shared mapping
   * |recorded_km|.
   */
  EmuFile::shr_ptr get_or_create(const KernelMapping& recorded_km,
                                 uint64_t file_size);

  /**
   * Dump information about this emufs to the "error" log.
   */
  void log() const;

  size_t size() const { return files.size(); }

  /** Create and return a new emufs. */
  static shr_ptr create();

  void destroyed_file(EmuFile& emu_file) { files.erase(FileId(emu_file)); }

private:
  EmuFs();

  struct FileId {
    FileId(const KernelMapping& recorded_map);
    FileId(const EmuFile& emu_file)
        : device(emu_file.device()), inode(emu_file.inode()) {}
    bool operator<(const FileId& other) const {
      return device < other.device ||
             (device == other.device && inode < other.inode);
    }
    dev_t device;
    ino_t inode;
  };

  typedef std::map<FileId, std::weak_ptr<EmuFile>> FileMap;

  FileMap files;

  EmuFs(const EmuFs&) = delete;
  EmuFs& operator=(const EmuFs&) = delete;
};

} // namespace rr

#endif // RR_EMUFS_H
