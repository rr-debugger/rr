/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_ADDRESS_SPACE_H_
#define RR_ADDRESS_SPACE_H_

#include <inttypes.h>
#include <sys/mman.h>

#include <map>
#include <memory>
#include <set>

#include "preload/preload_interface.h"

#include "kernel_abi.h"
#include "MemoryRange.h"
#include "Monkeypatcher.h"
#include "remote_code_ptr.h"
#include "TaskishUid.h"
#include "TraceStream.h"
#include "util.h"

class Session;
class Task;

/**
 * Base class for classes that manage a set of Tasks.
 */
class HasTaskSet {
public:
  typedef std::set<Task*> TaskSet;

  const TaskSet& task_set() const { return tasks; }

  void insert_task(Task* t);
  void erase_task(Task* t);

protected:
  TaskSet tasks;
};

/**
 * PseudoDevices aren't real disk devices, but they differentiate
 * memory mappings when we're trying to decide whether adjacent
 * FileId::NO_DEVICE mappings should be coalesced.
 */
enum PseudoDevice {
  PSEUDODEVICE_NONE = 0,
  PSEUDODEVICE_ANONYMOUS,
  PSEUDODEVICE_HEAP,
  PSEUDODEVICE_SCRATCH,
  PSEUDODEVICE_SHARED_MMAP_FILE,
  PSEUDODEVICE_STACK,
  PSEUDODEVICE_SYSCALLBUF,
  PSEUDODEVICE_VDSO,
  PSEUDODEVICE_SYSV_SHM
};

/**
 * FileIds uniquely identify a file at a point in time (when the file
 * is stat'd).
 */
class FileId {
public:
  static const dev_t NO_DEVICE = 0;
  static const ino_t NO_INODE = 0;

  FileId(PseudoDevice psdev = PSEUDODEVICE_NONE)
      : device(NO_DEVICE), inode(NO_INODE), psdev(psdev) {}
  FileId(const struct stat& st, PseudoDevice psdev = PSEUDODEVICE_NONE)
      : device(st.st_dev), inode(st.st_ino), psdev(psdev) {}
  FileId(dev_t dev, ino_t ino, PseudoDevice psdev = PSEUDODEVICE_NONE)
      : device(dev), inode(ino), psdev(psdev) {}
  FileId(dev_t dev_major, dev_t dev_minor, ino_t ino,
         PseudoDevice psdev = PSEUDODEVICE_NONE);

  /**
   * Return the major/minor ID for the device underlying this
   * file.  If |is_real_device()| is false, return 0
   * (NO_DEVICE).
   */
  dev_t dev_major() const;
  dev_t dev_minor() const;
  /**
   * Return a displayable "real" inode.  If |is_real_device()|
   * is false, return 0 (NO_INODE).
   */
  ino_t disp_inode() const;
  ino_t internal_inode() const { return inode; }
  PseudoDevice psuedodevice() const { return psdev; }

  /**
   * Return true iff |this| and |o| are the same "real device"
   * (i.e., same device and inode), or |this| and |o| are
   * ANONYMOUS pseudo-devices.  Results are undefined for other
   * pseudo-devices.
   */
  bool equivalent_to(const FileId& o) const {
    if (psdev != o.psdev) {
      return false;
    }
    if (psdev == PSEUDODEVICE_ANONYMOUS) {
      return true;
    }
    if (psdev != PSEUDODEVICE_SYSV_SHM) {
      if (dev_major() != o.dev_major()) {
        return false;
      }
      // Allow device minor numbers to vary if the major device is
      // 0. This was observed to be happening on
      // "3.13.0-24-generic #46-Ubuntu SMP" in KVM with btrfs.
      if (dev_major() != 0 && dev_minor() != o.dev_minor()) {
        return false;
      }
    }
    return inode == o.inode;
  }
  /**
   * Return true if this file is/was backed by an external
   * device, as opposed to a transient RAM mapping.
   */
  bool is_real_device() const {
    return device > NO_DEVICE || psdev == PSEUDODEVICE_SYSV_SHM;
  }
  const char* special_name() const;

  bool operator<(const FileId& o) const {
    return psdev != o.psdev ? psdev < o.psdev : device != o.device
                                                    ? device < o.device
                                                    : inode < o.inode;
  }

private:
  dev_t device;
  ino_t inode;
  PseudoDevice psdev;
};

/**
 * Describe the mapping of a MappableResource.  This includes the
 * offset of the mapping, its protection flags, the offest within the
 * resource, and more.
 */
class KernelMapping {
public:
  /**
   * These are the flags we track internally to distinguish
   * between adjacent segments.  For example, the kernel
   * considers a NORESERVE anonynmous mapping that's adjacent to
   * a non-NORESERVE mapping distinct, even if all other
   * metadata are the same.  See |is_adjacent_mapping()| in
   * task.cc.
   */
  static const int map_flags_mask = MAP_ANONYMOUS | MAP_NORESERVE |
                                    MAP_PRIVATE | MAP_SHARED | MAP_STACK |
                                    MAP_GROWSDOWN;
  static const int checkable_flags_mask = MAP_PRIVATE | MAP_SHARED;

  KernelMapping() : prot(0), flags(0), offset(0) {}
  KernelMapping(remote_ptr<void> addr, size_t num_bytes, int prot = 0, int flags = 0,
          off64_t offset = 0)
      : start(addr),
        end(addr + ceil_page_size(num_bytes)),
        prot(prot),
        flags(flags & map_flags_mask),
        offset(offset) {
    assert_valid();
  }
  KernelMapping(remote_ptr<void> start, remote_ptr<void> end, int prot = 0,
          int flags = 0, off64_t offset = 0)
      : start(start),
        end(end),
        prot(prot),
        flags(flags & map_flags_mask),
        offset(offset) {
    assert_valid();
  }

  KernelMapping(const KernelMapping& o)
      : start(o.start),
        end(o.end),
        prot(o.prot),
        flags(o.flags),
        offset(o.offset) {
  }
  KernelMapping operator=(const KernelMapping& o) {
    memcpy(this, &o, sizeof(*this));
    assert_valid();
    return *this;
  }

  void assert_valid() const {
    assert(end >= start);
    assert(num_bytes() % page_size() == 0);
    assert(!(flags & ~map_flags_mask));
    assert(offset % page_size() == 0);
  }

  /**
   * Return true iff |o| is an address range fully contained by
   * this.
   */
  bool has_subset(const KernelMapping& o) const {
    return start <= o.start && o.end <= end;
  }

  /**
   * Return true iff |o| and this map at least one shared byte.
   */
  bool intersects(const KernelMapping& o) const {
    return (start == o.start && o.end == end) ||
           (start <= o.start && o.start < end) ||
           (start < o.end && o.end <= end);
  }

  size_t num_bytes() const {
    ssize_t s = end - start;
    assert(s >= 0);
    return s;
  }

  /**
   * Return the lowest-common-denominator interpretation of this
   * mapping, namely, the one that can be parsed out of
   * /proc/maps.
   */
  KernelMapping to_kernel() const {
    return KernelMapping(start, end, prot, flags & checkable_flags_mask, offset);
  }

  /**
   * Dump a representation of |this| to a string in a format
   * similar to the former part of /proc/[tid]/maps.
  */
  std::string str() const {
    char str[200];
    sprintf(str, "%8p-%8p %c%c%c%c %08" PRIx64, (void*)start.as_int(),
            (void*)end.as_int(), (PROT_READ & prot) ? 'r' : '-',
            (PROT_WRITE & prot) ? 'w' : '-', (PROT_EXEC & prot) ? 'x' : '-',
            (MAP_SHARED & flags) ? 's' : 'p', offset);
    return str;
  }

  /**
   * Super-dangerous! Only call this if it's guaranteed not to change
   * the ordering of Mappings.
   */
  void update_start(remote_ptr<void> new_start) const {
    *const_cast<remote_ptr<void>*>(&start) = new_start;
  }

  const remote_ptr<void> start;
  const remote_ptr<void> end;
  const int prot;
  const int flags;
  const off64_t offset;
};
std::ostream& operator<<(std::ostream& o, const KernelMapping& m);

/**
 * Compare |a| and |b| so that "subset" lookups will succeed.  What
 * does that mean?  If |a| and |b| overlap (intersect), then this
 * comparator considers them equivalent.  That means that if |a|
 * represents one byte within a mapping |b|, then |a| and |b| will be
 * considered equivalent.
 *
 * If |a| and |b| don't overlap, return true if |a|'s start addres is
 * less than |b|'s/
 */
struct MappingComparator {
  bool operator()(const KernelMapping& a, const KernelMapping& b) const {
    return a.intersects(b) ? false : a.start < b.start;
  }
};

/**
 * A resource that can be mapped into RAM.  |Mapping| represents a
 * mapping into RAM of a MappableResource.
 */
struct MappableResource {
  MappableResource() : id(FileId()) {}
  MappableResource(const FileId& id) : id(id) {}
  MappableResource(const FileId& id, const std::string& fsname)
      : id(id), fsname(fsname) {}

  bool operator==(const MappableResource& o) const {
    return id.equivalent_to(o.id);
  }
  bool operator!=(const MappableResource& o) const { return !(*this == o); }
  bool is_scratch() const { return PSEUDODEVICE_SCRATCH == id.psuedodevice(); }
  bool is_shared_mmap_file() const {
    return PSEUDODEVICE_SHARED_MMAP_FILE == id.psuedodevice() ||
           PSEUDODEVICE_SYSV_SHM == id.psuedodevice();
  }
  bool is_stack() const { return PSEUDODEVICE_STACK == id.psuedodevice(); }

  void remove_stackness() {
    if (is_stack()) {
      id = FileId(id.dev_major(), id.dev_minor(), id.internal_inode(),
                  PSEUDODEVICE_ANONYMOUS);
      fsname = "";
    }
  }

  /**
   * Return a representation of this resource that would be
   * parsed from /proc/maps if this were mapped.
   */
  MappableResource to_kernel() const {
    PseudoDevice psdev;
    switch (id.psuedodevice()) {
      case PSEUDODEVICE_STACK:
      case PSEUDODEVICE_SCRATCH:
      case PSEUDODEVICE_ANONYMOUS:
        psdev = PSEUDODEVICE_ANONYMOUS;
        break;
      case PSEUDODEVICE_SYSV_SHM:
        psdev = PSEUDODEVICE_SYSV_SHM;
        break;
      default:
        psdev = PSEUDODEVICE_NONE;
        break;
    }

    return MappableResource(
        FileId(id.dev_major(), id.dev_minor(), id.disp_inode(), psdev),
        fsname.c_str());
  }

  /**
   * Dump a representation of |this| to a string in a format
   * similar to the tail part of /proc/[tid]/maps. Some extra
   * informations are put in a '()'.
  */
  std::string str() const {
    char str[200];
    sprintf(str, "%02" PRIx64 ":%02" PRIx64 " %-10ld %s %s", id.dev_major(),
            id.dev_minor(), id.disp_inode(), fsname.c_str(), id.special_name());
    return str;
  }

  static MappableResource anonymous() {
    return FileId(FileId::NO_DEVICE, nr_anonymous_maps++,
                  PSEUDODEVICE_ANONYMOUS);
  }
  static MappableResource heap() {
    return MappableResource(
        FileId(FileId::NO_DEVICE, FileId::NO_INODE, PSEUDODEVICE_HEAP),
        "[heap]");
  }
  static MappableResource scratch(pid_t tid) {
    return MappableResource(
        FileId(FileId::NO_DEVICE, tid, PSEUDODEVICE_SCRATCH), "[scratch]");
  }
  static MappableResource shared_mmap_file(const TraceMappedRegion& file);
  static MappableResource shared_mmap_anonymous(uint32_t unique_id) {
    return MappableResource(
        FileId(FileId::NO_DEVICE, unique_id, PSEUDODEVICE_SHARED_MMAP_FILE));
  }
  static MappableResource stack(pid_t tid) {
    return MappableResource(FileId(FileId::NO_DEVICE, tid, PSEUDODEVICE_STACK),
                            "[stack]");
  }
  static MappableResource syscallbuf(pid_t tid, int fd, const char* path);

  FileId id;
  /**
   * Some name that this file may have on its underlying file
   * system.
   */
  std::string fsname;

  static ino_t nr_anonymous_maps;
};

enum TrapType {
  TRAP_NONE = 0,
  // Trap for debugger 'stepi' request.
  TRAP_STEPI,
  // Trap for internal rr purposes, f.e. replaying async
  // signals.
  TRAP_BKPT_INTERNAL,
  // Trap on behalf of a debugger user.
  TRAP_BKPT_USER,
};

enum WatchType {
  // NB: these random-looking enumeration values are chosen to
  // match the numbers programmed into x86 debug registers.
  WATCH_EXEC = 0x00,
  WATCH_WRITE = 0x01,
  WATCH_READWRITE = 0x03
};

enum DebugStatus {
  DS_WATCHPOINT_ANY = 0xf,
  DS_SINGLESTEP = 1 << 14,
};

/**
 * A distinct watchpoint, corresponding to the information needed to
 * program a single x86 debug register.
 */
struct WatchConfig {
  WatchConfig(remote_ptr<void> addr, size_t num_bytes, WatchType type)
      : addr(addr), num_bytes(num_bytes), type(type) {}
  remote_ptr<void> addr;
  size_t num_bytes;
  WatchType type;
};

/**
 * Models the address space for a set of tasks.  This includes the set
 * of mapped pages, and the resources those mappings refer to.
 */
class AddressSpace : public HasTaskSet {
  friend class Session;
  friend struct VerifyAddressSpace;

public:
  typedef std::map<KernelMapping, MappableResource, MappingComparator> MemoryMap;
  typedef std::shared_ptr<AddressSpace> shr_ptr;

  ~AddressSpace();

  /**
   * Call this after a new task has been cloned within this
   * address space.
   */
  void after_clone();

  /**
   * Call this after a successful execve syscall has completed. At this point
   * it is safe to perform remote syscalls.
   */
  void post_exec_syscall(Task* t);

  /**
   * Change the program data break of this address space to
   * |addr|.
   */
  void brk(remote_ptr<void> addr);

  /**
   * Dump a representation of |this| to stderr in a format
   * similar to /proc/[tid]/maps.
   *
   * XXX/ostream-ify me.
   */
  void dump() const;

  /**
   * Return true if this was created as the result of an exec()
   * call, instead of cloned from another address space.
   */
  bool execed() const { return !is_clone; }

  /**
   * Return tid of the first task for this address space.
   */
  pid_t leader_tid() const { return leader_tid_; }

  /**
   * Return AddressSpaceUid for this address space.
   */
  AddressSpaceUid uid() const {
    return AddressSpaceUid(leader_tid_, leader_serial, exec_count);
  }

  Session* session() const { return session_; }

  /**
   * Return the path this address space was exec()'d with.
   */
  const std::string& exe_image() const { return exe; }

  /**
   * Assuming the last retired instruction has raised a SIGTRAP
   * and might be a breakpoint trap instruction, return the type
   * of breakpoint set at |ip() - sizeof(breakpoint_insn)|, if
   * one exists.  Otherwise return TRAP_NONE.
   */
  TrapType get_breakpoint_type_for_retired_insn(remote_code_ptr ip);

  /**
   * Return the type of breakpoint that's been registered for
   * |addr|.
   */
  TrapType get_breakpoint_type_at_addr(remote_code_ptr addr);

  /**
   * The buffer |dest| of length |length| represents the contents of tracee
   * memory at |addr|. Replace the bytes in |dest| that have been overwritten
   * by breakpoints with the original data that was replaced by the breakpoints.
   */
  void replace_breakpoints_with_original_values(uint8_t* dest, size_t length,
                                                remote_ptr<uint8_t> addr);

  /**
   * Map |num_bytes| into this address space at |addr|, with
   * |prot| protection and |flags|.  The pages are (possibly
   * initially) backed starting at |offset| of |res|.
   */
  void map(remote_ptr<void> addr, size_t num_bytes, int prot, int flags,
           off64_t offset_bytes, const MappableResource& res);

  /**
   * Return the mapping and mapped resource for the byte at address 'addr'.
   * There must be such a mapping.
   */
  MemoryMap::value_type mapping_of(remote_ptr<void> addr) const;

  /**
   * Return true if there is some mapping for the byte at 'addr'.
   */
  bool has_mapping(remote_ptr<void> addr) const;

  /**
   * Return the memory map.
   */
  const MemoryMap& memmap() const { return mem; }

  /**
   * Change the protection bits of [addr, addr + num_bytes) to
   * |prot|.
   */
  void protect(remote_ptr<void> addr, size_t num_bytes, int prot);

  /**
   * Move the mapping [old_addr, old_addr + old_num_bytes) to
   * [new_addr, old_addr + new_num_bytes), preserving metadata.
   */
  void remap(remote_ptr<void> old_addr, size_t old_num_bytes,
             remote_ptr<void> new_addr, size_t new_num_bytes);

  /**
   * Notify that the stack segment 'mapping' has grown down to a new start
   * address.
   */
  void fix_stack_segment_start(const KernelMapping& mapping,
                               remote_ptr<void> new_start);

  /**
   * Notify that data was written to this address space by rr or
   * by the kernel.
   */
  void notify_written(remote_ptr<void> addr, size_t num_bytes);

  /** Ensure a breakpoint of |type| is set at |addr|. */
  bool add_breakpoint(remote_code_ptr addr, TrapType type);
  /**
   * Remove a |type| reference to the breakpoint at |addr|.  If
   * the removed reference was the last, the breakpoint is
   * destroyed.
   */
  void remove_breakpoint(remote_code_ptr addr, TrapType type);
  /**
   * Destroy all breakpoints in this VM, regardless of their
   * reference counts.
   */
  void remove_all_breakpoints();

  /**
   * Manage watchpoints.  Analogous to breakpoint-managing
   * methods above, except that watchpoints can be set for an
   * address range.
   */
  bool add_watchpoint(remote_ptr<void> addr, size_t num_bytes, WatchType type);
  void remove_watchpoint(remote_ptr<void> addr, size_t num_bytes,
                         WatchType type);
  void remove_all_watchpoints();
  std::vector<WatchConfig> all_watchpoints();

  /**
   * Save all watchpoint state onto a stack.
   */
  void save_watchpoints();
  /**
   * Pop all watchpoint state from the saved-state stack.
   */
  bool restore_watchpoints();

  /**
   * Notify that at least one watchpoint was hit --- recheck them all.
   * Returns true if any watchpoint actually triggered. Note that
   * debug_status can indicate a hit watchpoint that doesn't actually
   * trigger, because the value of a write-watchpoint did not change.
   * Likewise, debug_status can indicate a watchpoint wasn't hit that
   * actually was (because in some configurations, e.g. VMWare
   * hypervisor with 32-bit x86 guest, debug_status watchpoint bits
   * are known to not be set on singlestep).
   */
  bool notify_watchpoint_fired(uintptr_t debug_status);
  /**
   * Return all changed watchpoints in |watches| and clear their changed flags.
   */
  std::vector<WatchConfig> consume_watchpoint_changes();

  /**
   * Make [addr, addr + num_bytes) inaccesible within this
   * address space.
   */
  void unmap(remote_ptr<void> addr, ssize_t num_bytes);

  /**
   * Notification of madvise call.
   */
  void advise(remote_ptr<void> addr, ssize_t num_bytes, int advice);

  /** Return the vdso mapping of this. */
  KernelMapping vdso() const;

  /**
   * Verify that this cached address space matches what the
   * kernel thinks it should be.
   */
  void verify(Task* t) const;

  void for_all_mappings(
      std::function<void(const KernelMapping& m, const MappableResource& r)> f);
  void for_all_mappings_in_range(
      std::function<void(const KernelMapping& m, const MappableResource& r)> f,
      const MemoryRange& range);

  bool has_breakpoints() { return !breakpoints.empty(); }
  bool has_watchpoints() { return !watchpoints.empty(); }

  // Encoding of the |int $3| instruction.
  static const uint8_t breakpoint_insn = 0xCC;

  ScopedFd& mem_fd() { return child_mem_fd; }
  void set_mem_fd(ScopedFd&& fd) { child_mem_fd = std::move(fd); }

  Monkeypatcher& monkeypatcher() { return monkeypatch_state; }

  void at_preload_init(Task* t);

  /* The address of the syscall instruction from which traced syscalls made by
   * the syscallbuf will originate. */
  remote_code_ptr traced_syscall_ip() const { return traced_syscall_ip_; }
  /* The address of the syscall instruction from which untraced syscalls will
   * originate, used to determine whether a syscall is being
   * made by the syscallbuf wrappers or not. */
  remote_code_ptr untraced_syscall_ip() const { return untraced_syscall_ip_; }
  /* The address of the syscall instruction from which privileged traced
   * syscalls made by the syscallbuf will originate. */
  remote_code_ptr privileged_traced_syscall_ip() const {
    return privileged_traced_syscall_ip_;
  }
  /* The address of the syscall instruction from which privileged untraced
   * syscalls will originate, used to determine whether a syscall is being
   * made by the syscallbuf wrappers or not. */
  remote_code_ptr privileged_untraced_syscall_ip() const {
    return privileged_untraced_syscall_ip_;
  }
  /* Start and end of the mapping of the syscallbuf code
   * section, used to determine whether a tracee's $ip is in the
   * lib. */
  remote_ptr<void> syscallbuf_lib_start() const {
    return syscallbuf_lib_start_;
  }
  remote_ptr<void> syscallbuf_lib_end() const { return syscallbuf_lib_end_; }

  bool syscallbuf_enabled() const { return syscallbuf_lib_start_ != nullptr; }

  /**
   * We'll map a page of memory here into every exec'ed process for our own
   * use.
   */
  static remote_ptr<void> rr_page_start() { return RR_PAGE_ADDR; }
  /**
   * This might not be the length of an actual system page, but we allocate
   * at least this much space.
   */
  static uint32_t rr_page_size() { return 4096; }
  static remote_ptr<void> rr_page_end() {
    return rr_page_start() + rr_page_size();
  }
  /**
   * ip() when we're in an untraced system call; same for all supported
   * architectures (hence static).
   */
  static remote_code_ptr rr_page_ip_in_untraced_syscall() {
    return RR_PAGE_IN_UNTRACED_SYSCALL_ADDR;
  }
  /**
   * This doesn't need to be the same for all architectures, but may as well
   * make it so.
   */
  static remote_code_ptr rr_page_ip_in_traced_syscall() {
    return RR_PAGE_IN_TRACED_SYSCALL_ADDR;
  }
  /**
   * ip() when we're in an untraced system call; same for all supported
   * architectures (hence static).
   */
  static remote_code_ptr rr_page_ip_in_privileged_untraced_syscall() {
    return RR_PAGE_IN_PRIVILEGED_UNTRACED_SYSCALL_ADDR;
  }
  /**
   * This doesn't need to be the same for all architectures, but may as well
   * make it so.
   */
  static remote_code_ptr rr_page_ip_in_privileged_traced_syscall() {
    return RR_PAGE_IN_PRIVILEGED_TRACED_SYSCALL_ADDR;
  }
  /**
   * ip() of the untraced traced system call instruction.
   */
  remote_code_ptr rr_page_untraced_syscall_ip(SupportedArch arch) {
    return rr_page_ip_in_untraced_syscall().decrement_by_syscall_insn_length(
        arch);
  }
  /**
   * ip() of the traced traced system call instruction.
   */
  remote_code_ptr rr_page_traced_syscall_ip(SupportedArch arch) {
    return rr_page_ip_in_traced_syscall().decrement_by_syscall_insn_length(
        arch);
  }
  /**
   * ip() of the privileged untraced traced system call instruction.
   */
  remote_code_ptr rr_page_privileged_untraced_syscall_ip(SupportedArch arch) {
    return rr_page_ip_in_privileged_untraced_syscall()
        .decrement_by_syscall_insn_length(arch);
  }
  /**
   * ip() of the privileged traced traced system call instruction.
   */
  remote_code_ptr rr_page_privileged_traced_syscall_ip(SupportedArch arch) {
    return rr_page_ip_in_privileged_traced_syscall()
        .decrement_by_syscall_insn_length(arch);
  }

  /**
   * Locate a syscall instruction in t's VDSO.
   * This gives us a way to execute remote syscalls without having to write
   * a syscall instruction into executable tracee memory (which might not be
   * possible with some kernels, e.g. PaX).
   */
  remote_code_ptr find_syscall_instruction(Task* t);

  /**
   * Task |t| just forked from this address space. Apply dont_fork settings.
   */
  void did_fork_into(Task* t);

  void set_first_run_event(TraceFrame::Time event) { first_run_event_ = event; }
  TraceFrame::Time first_run_event() { return first_run_event_; }

  const std::vector<uint8_t>& saved_auxv() { return saved_auxv_; }
  void save_auxv(Task* t);

private:
  class Breakpoint;
  typedef std::map<remote_code_ptr, Breakpoint> BreakpointMap;
  class Watchpoint;

  AddressSpace(Task* t, const std::string& exe, uint32_t exec_count);
  AddressSpace(Session* session, const AddressSpace& o, pid_t leader_tid,
               uint32_t leader_serial, uint32_t exec_count);

  void unmap_internal(remote_ptr<void> addr, ssize_t num_bytes);

  void map_rr_page(Task* t);

  bool update_watchpoint_value(const MemoryRange& range,
                               Watchpoint& watchpoint);
  void update_watchpoint_values(remote_ptr<void> start, remote_ptr<void> end);
  enum WatchpointFilter { ALL_WATCHPOINTS, CHANGED_WATCHPOINTS };
  std::vector<WatchConfig> get_watchpoints_internal(WatchpointFilter filter);

  enum WillSetTaskState { SETTING_TASK_STATE, NOT_SETTING_TASK_STATE };
  std::vector<WatchConfig> get_watch_configs(
      WillSetTaskState will_set_task_state);

  /**
   * Construct a minimal set of watchpoints to be enabled based
   * on |set_watchpoint()| calls, and program them for each task
   * in this address space.
   */
  bool allocate_watchpoints();

  /**
   * Merge the mappings adjacent to |it| in memory that are
   * semantically "adjacent mappings" of the same resource as
   * well, for example have adjacent file offsets and the same
   * prot and flags.
   */
  void coalesce_around(MemoryMap::iterator it);

  /**
   * Erase |it| from |breakpoints| and restore any memory in
   * this it may have overwritten.
   */
  void destroy_breakpoint(BreakpointMap::const_iterator it);

  /**
   * For each mapped segment overlapping [addr, addr +
   * num_bytes), call |f|.  Pass |f| the overlapping mapping,
   * the mapped resource, and the range of addresses remaining
   * to be iterated over.
   *
   * Pass |ITERATE_CONTIGUOUS| to stop iterating when the last
   * contiguous mapping after |addr| within the region is seen.
   * Default is to iterate all mappings in the region.
   */
  enum { ITERATE_DEFAULT, ITERATE_CONTIGUOUS };
  void for_each_in_range(
      remote_ptr<void> addr, ssize_t num_bytes,
      std::function<void(const KernelMapping& m, const MappableResource& r,
                         const KernelMapping& rem)> f,
      int how = ITERATE_DEFAULT);

  /**
   * Map |m| of |r| into this address space, and coalesce any
   * mappings of |r| that are adjacent to |m|.
   */
  void map_and_coalesce(const KernelMapping& m, const MappableResource& r);

  /** Set the dynamic heap segment to |[start, end)| */
  void update_heap(remote_ptr<void> start, remote_ptr<void> end) {
    heap = KernelMapping(start, end, PROT_READ | PROT_WRITE,
                   MAP_ANONYMOUS | MAP_PRIVATE, 0);
  }

  template <typename Arch> void at_preload_init_arch(Task* t);

  enum { EXEC_BIT = 1 << 0, READ_BIT = 1 << 1, WRITE_BIT = 1 << 2 };

  /** Return the access bits above needed to watch |type|. */
  static int access_bits_of(WatchType type);

  /**
   * Represents a refcount set on a particular address.  Because there
   * can be multiple refcounts of multiple types set on a single
   * address, Breakpoint stores explicit USER and INTERNAL breakpoint
   * refcounts.  Clients adding/removing breakpoints at this addr must
   * call ref()/unref() as appropropiate.
   */
  struct Breakpoint {
    Breakpoint() : internal_count(0), user_count(0) {}
    Breakpoint(const Breakpoint& o) = default;
    // AddressSpace::destroy_all_breakpoints() can cause this
    // destructor to be invoked while we have nonzero total
    // refcount, so the most we can assert is that the refcounts
    // are valid.
    ~Breakpoint() { assert(internal_count >= 0 && user_count >= 0); }

    void ref(TrapType which) {
      assert(internal_count >= 0 && user_count >= 0);
      ++*counter(which);
    }
    int unref(TrapType which) {
      assert(internal_count > 0 || user_count > 0);
      --*counter(which);
      assert(internal_count >= 0 && user_count >= 0);
      return internal_count + user_count;
    }

    TrapType type() const {
      // NB: USER breakpoints need to be processed before
      // INTERNAL ones.  We want to give the debugger a
      // chance to dispatch commands before we attend to the
      // internal rr business.  So if there's a USER "ref"
      // on the breakpoint, treat it as a USER breakpoint.
      return user_count > 0 ? TRAP_BKPT_USER : TRAP_BKPT_INTERNAL;
    }

    size_t data_length() { return 1; }
    uint8_t* original_data() { return &overwritten_data; }

    // "Refcounts" of breakpoints set at |addr|.  The breakpoint
    // object must be unique since we have to save the overwritten
    // data, and we can't enforce the order in which breakpoints
    // are set/removed.
    int internal_count, user_count;
    uint8_t overwritten_data;
    static_assert(sizeof(overwritten_data) ==
                      sizeof(AddressSpace::breakpoint_insn),
                  "Must have the same size.");

    int* counter(TrapType which) {
      assert(TRAP_BKPT_INTERNAL == which || TRAP_BKPT_USER == which);
      int* p = TRAP_BKPT_USER == which ? &user_count : &internal_count;
      assert(*p >= 0);
      return p;
    }
  };

  // XXX one is tempted to merge Breakpoint and Watchpoint into a single
  // entity, but the semantics are just different enough that separate
  // objects are easier for now.
  /**
   * Track the watched accesses of a contiguous range of memory
   * addresses.
   */
  class Watchpoint {
  public:
    Watchpoint(size_t num_bytes)
        : exec_count(0),
          read_count(0),
          write_count(0),
          value_bytes(num_bytes),
          valid(false),
          changed(false) {}
    Watchpoint(const Watchpoint&) = default;
    ~Watchpoint() { assert_valid(); }

    void watch(int which) {
      assert_valid();
      exec_count += (EXEC_BIT & which) != 0;
      read_count += (READ_BIT & which) != 0;
      write_count += (WRITE_BIT & which) != 0;
    }
    int unwatch(int which) {
      assert_valid();
      if (EXEC_BIT & which) {
        assert(exec_count > 0);
        --exec_count;
      }
      if (READ_BIT & which) {
        assert(read_count > 0);
        --read_count;
      }
      if (WRITE_BIT & which) {
        assert(write_count > 0);
        --write_count;
      }
      return exec_count + read_count + write_count;
    }

    int watched_bits() const {
      return (exec_count > 0 ? EXEC_BIT : 0) | (read_count > 0 ? READ_BIT : 0) |
             (write_count > 0 ? WRITE_BIT : 0);
    }

    void assert_valid() const {
      assert(exec_count >= 0 && read_count >= 0 && write_count >= 0);
    }

    // Watchpoints stay alive until all watched access typed have
    // been cleared.  We track refcounts of each watchable access
    // separately.
    int exec_count, read_count, write_count;
    // Debug registers allocated for read/exec access checking.
    // Write watchpoints are always triggered by checking for actual memory
    // value changes. Read/exec watchpoints can't be triggered that way, so
    // we look for these registers being triggered instead.
    std::vector<int8_t> debug_regs_for_exec_read;
    std::vector<uint8_t> value_bytes;
    bool valid;
    bool changed;
  };

  // All breakpoints set in this VM.
  BreakpointMap breakpoints;
  /* Path of the executable image this address space was
   * exec()'d with. */
  std::string exe;
  /* Pid of first task for this address space */
  pid_t leader_tid_;
  /* Serial number of first task for this address space */
  uint32_t leader_serial;
  uint32_t exec_count;
  /* Track the special process-global heap in order to support
   * adjustments by brk(). */
  KernelMapping heap;
  /* Were we cloned from another address space? */
  bool is_clone;
  /* All segments mapped into this address space. */
  MemoryMap mem;
  /* madvise DONTFORK regions */
  std::set<MemoryRange> dont_fork;
  // The session that created this.  We save a ref to it so that
  // we can notify it when we die.
  Session* session_;
  /* First mapped byte of the vdso. */
  remote_ptr<void> vdso_start_addr;
  // The monkeypatcher that's handling this address space.
  Monkeypatcher monkeypatch_state;
  // The watchpoints set for tasks in this VM.  Watchpoints are
  // programmed per Task, but we track them per address space on
  // behalf of debuggers that assume that model.
  std::map<MemoryRange, Watchpoint> watchpoints;
  std::vector<std::map<MemoryRange, Watchpoint> > saved_watchpoints;
  // Tracee memory is read and written through this fd, which is
  // opened for the tracee's magic /proc/[tid]/mem device.  The
  // advantage of this over ptrace is that we can access it even
  // when the tracee isn't at a ptrace-stop.  It's also
  // theoretically faster for large data transfers, which rr can
  // do often.
  //
  // Users of child_mem_fd should fall back to ptrace-based memory
  // access when child_mem_fd is not open.
  ScopedFd child_mem_fd;
  remote_code_ptr traced_syscall_ip_;
  remote_code_ptr untraced_syscall_ip_;
  remote_code_ptr privileged_traced_syscall_ip_;
  remote_code_ptr privileged_untraced_syscall_ip_;
  remote_ptr<void> syscallbuf_lib_start_;
  remote_ptr<void> syscallbuf_lib_end_;

  std::vector<uint8_t> saved_auxv_;

  /**
   * The time of the first event that ran code for a task in this address space.
   * 0 if no such event has occurred.
   */
  TraceFrame::Time first_run_event_;

  /**
   * For each architecture, the offset of a syscall instruction with that
   * architecture's VDSO, or 0 if not known.
   */
  static uint32_t offset_to_syscall_in_vdso[SupportedArch_MAX + 1];

  /**
   * Ensure that the cached mapping of |t| matches /proc/maps,
   * using adjancent-map-merging heuristics that are as lenient
   * as possible given the data available from /proc/maps.
   */
  static void check_segment_iterator(void* vasp, Task* t,
                                     const struct map_iterator_data* data);

  /**
   * After an exec, populate the new address space of |t| with
   * the existing mappings we find in /proc/maps.
   */
  static void populate_address_space(void* asp, Task* t,
                                     const struct map_iterator_data* data);

  AddressSpace operator=(const AddressSpace&) = delete;
};

#endif /* RR_ADDRESS_SPACE_H_ */
