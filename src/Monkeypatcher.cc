/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "Monkeypatcher.h"

#include <limits.h>
#include <linux/auxvec.h>

#include <sstream>

#include "AddressSpace.h"
#include "AutoRemoteSyscalls.h"
#include "ElfReader.h"
#include "Flags.h"
#include "RecordSession.h"
#include "RecordTask.h"
#include "ReplaySession.h"
#include "ScopedFd.h"
#include "core.h"
#include "kernel_abi.h"
#include "kernel_metadata.h"
#include "log.h"

using namespace std;

namespace rr {

#include "AssemblyTemplates.generated"

static void write_and_record_bytes(RecordTask* t, remote_ptr<void> child_addr,
                                   size_t size, const void* buf, bool* ok = nullptr) {
  t->write_bytes_helper(child_addr, size, buf, ok);
  if (!ok || *ok) {
    t->record_local(child_addr, size, buf);
  }
}

template <size_t N>
static void write_and_record_bytes(RecordTask* t, remote_ptr<void> child_addr,
                                   const uint8_t (&buf)[N], bool* ok = nullptr) {
  write_and_record_bytes(t, child_addr, N, buf, ok);
}

template <typename T>
static void write_and_record_mem(RecordTask* t, remote_ptr<T> child_addr,
                                 const T* val, int count) {
  t->write_bytes_helper(child_addr, sizeof(*val) * count,
                        static_cast<const void*>(val));
  t->record_local(child_addr, sizeof(T) * count, val);
}

/**
 * RecordSession sets up an LD_PRELOAD environment variable with an entry
 * SYSCALLBUF_LIB_FILENAME_PADDED (and, if enabled, an LD_AUDIT environment
 * variable with an entry RTLDAUDIT_LIB_FILENAME_PADDED) which is big enough to
 * hold either the 32-bit or 64-bit preload/audit library file names.
 * Immediately after exec we enter this function, which patches the environment
 * variable value with the correct library name for the task's architecture.
 *
 * It's possible for this to fail if a tracee alters the LD_PRELOAD value
 * and then does an exec. That's just too bad. If we ever have to handle that,
 * we should modify the environment passed to the exec call. This function
 * failing isn't necessarily fatal; a tracee might not rely on the functions
 * overridden by the preload library, or might override them itself (e.g.
 * because we're recording an rr replay).
 */
#define setup_library_path(arch, env_var, soname, task) \
  setup_library_path_arch<arch>(task, env_var, soname ## _BASE, \
                                soname ## _PADDED, soname ## _32)

template <typename Arch>
static void setup_library_path_arch(RecordTask* t, const char* env_var,
                                    const char* soname_base,
                                    const char* soname_padded,
                                    const char* soname_32) {
  const char* lib_name =
      sizeof(typename Arch::unsigned_word) < sizeof(uintptr_t)
          ? soname_32
          : soname_padded;
  auto env_assignment = string(env_var) + "=";

  auto p = t->regs().sp().cast<typename Arch::unsigned_word>();
  auto argc = t->read_mem(p);
  p += 1 + argc + 1; // skip argc, argc parameters, and trailing NULL
  while (true) {
    auto envp = t->read_mem(p);
    if (!envp) {
      LOG(debug) << env_var << " not found";
      return;
    }
    string env = t->read_c_str(envp);
    if (env.find(env_assignment) != 0) {
      ++p;
      continue;
    }
    size_t lib_pos = env.find(soname_base);
    if (lib_pos == string::npos) {
      LOG(debug) << soname_base << " not found in " << env_var;
      return;
    }
    size_t next_colon = env.find(':', lib_pos);
    if (next_colon != string::npos) {
      while ((next_colon + 1 < env.length()) &&
             (env[next_colon + 1] == ':' || env[next_colon + 1] == 0)) {
        ++next_colon;
      }
      if (next_colon + 1 <
          lib_pos + sizeof(soname_padded) - 1) {
        LOG(debug) << "Insufficient space for " << lib_name
                   << " in " << env_var << " before next ':'";
        return;
      }
    }
    if (env.length() < lib_pos + sizeof(soname_padded) - 1) {
      LOG(debug) << "Insufficient space for " << lib_name
                 << " in " << env_var << " before end of string";
      return;
    }
    remote_ptr<void> dest = envp + lib_pos;
    write_and_record_mem(t, dest.cast<char>(), lib_name, strlen(soname_padded));
    return;
  }
}

template <typename Arch> static void setup_preload_library_path(RecordTask* t) {
  static_assert(sizeof(SYSCALLBUF_LIB_FILENAME_PADDED) ==
                    sizeof(SYSCALLBUF_LIB_FILENAME_32),
                "filename length mismatch");
  setup_library_path(Arch, "LD_PRELOAD", SYSCALLBUF_LIB_FILENAME, t);
}

template <typename Arch> static void setup_audit_library_path(RecordTask* t) {
  static_assert(sizeof(RTLDAUDIT_LIB_FILENAME_PADDED) ==
                    sizeof(RTLDAUDIT_LIB_FILENAME_32),
                "filename length mismatch");
  if (t->session().use_audit()) {
    setup_library_path(Arch, "LD_AUDIT", RTLDAUDIT_LIB_FILENAME, t);
  }
}

void Monkeypatcher::init_dynamic_syscall_patching(
    RecordTask* t, int syscall_patch_hook_count,
    remote_ptr<struct syscall_patch_hook> syscall_patch_hooks) {
  if (syscall_patch_hook_count && syscall_hooks.empty()) {
    syscall_hooks = t->read_mem(syscall_patch_hooks, syscall_patch_hook_count);
  }
}

template <typename Arch>
static bool patch_syscall_with_hook_arch(Monkeypatcher& patcher, RecordTask* t,
                                         const syscall_patch_hook& hook,
                                         size_t instruction_length,
                                         uint32_t fake_syscall_number);

template <typename StubPatch>
static void substitute(uint8_t* buffer, uint64_t return_addr,
                       uint32_t trampoline_relative_addr);

template <typename ExtendedJumpPatch>
static void substitute_extended_jump(uint8_t* buffer, uint64_t patch_addr,
                                     uint64_t return_addr,
                                     uint64_t target_addr,
                                     uint32_t fake_syscall_number,
                                     uint8_t stub[20]);

template <>
void substitute_extended_jump<X86SyscallStubExtendedJump>(
    uint8_t* buffer, uint64_t patch_addr, uint64_t return_addr,
    uint64_t target_addr, uint32_t, uint8_t stub[STUB_PATCH_LENGTH]) {
  int64_t offset =
      target_addr -
      (patch_addr + X86SyscallStubExtendedJump::trampoline_relative_addr_end);
  int64_t ret_offset =
      return_addr -
      (patch_addr + X86SyscallStubExtendedJump::return_addr_relative_end);
  // An offset that appears to be > 2GB is OK here, since EIP will just
  // wrap around.
  X86SyscallStubExtendedJump::substitute(buffer, (uint32_t)offset, (char*)stub,
                                         (uint32_t)ret_offset);
}

template <>
void substitute_extended_jump<X64SyscallStubExtendedJump>(
    uint8_t* buffer, uint64_t, uint64_t return_addr, uint64_t target_addr,
    uint32_t, uint8_t stub[STUB_PATCH_LENGTH]) {
  X64SyscallStubExtendedJump::substitute(buffer, (char*)stub,
                                         target_addr, return_addr);
}

template <>
void substitute_extended_jump<X86TrapInstructionStubExtendedJump>(
    uint8_t* buffer, uint64_t patch_addr, uint64_t return_addr,
    uint64_t target_addr, uint32_t fake_syscall_number, uint8_t stub[STUB_PATCH_LENGTH]) {
  int64_t offset =
      target_addr -
      (patch_addr + X86SyscallStubExtendedJump::trampoline_relative_addr_end);
  int64_t ret_offset =
      return_addr -
      (patch_addr + X86SyscallStubExtendedJump::return_addr_relative_end);
  // An offset that appears to be > 2GB is OK here, since EIP will just
  // wrap around.
  X86TrapInstructionStubExtendedJump::substitute(buffer,
                                         fake_syscall_number, (uint32_t)offset,
                                         (char*)stub, (uint32_t)ret_offset);
}

template <>
void substitute_extended_jump<X64TrapInstructionStubExtendedJump>(
    uint8_t* buffer, uint64_t, uint64_t return_addr, uint64_t target_addr,
    uint32_t fake_syscall_number, uint8_t stub[STUB_PATCH_LENGTH]) {
  X64TrapInstructionStubExtendedJump::substitute(buffer, fake_syscall_number, (char*)stub,
                                        target_addr, return_addr);
}

/**
 * Allocate an extended jump in an extended jump page and return its address.
 * The resulting address must be within 2G of from_end, and the instruction
 * there must jump to to_start.
 */
template <typename ExtendedJumpPatch>
static remote_ptr<uint8_t> allocate_extended_jump_x86ish(
    RecordTask* t, vector<Monkeypatcher::ExtendedJumpPage>& pages,
    remote_ptr<uint8_t> from_end) {
  Monkeypatcher::ExtendedJumpPage* page = nullptr;
  for (auto& p : pages) {
    remote_ptr<uint8_t> page_jump_start = p.addr + p.allocated;
    int64_t offset = page_jump_start - from_end;
    if ((int32_t)offset == offset &&
        p.allocated + ExtendedJumpPatch::size <= page_size()) {
      page = &p;
      break;
    }
  }

  if (!page) {
    // We're looking for a gap of three pages --- one page to allocate and
    // a page on each side as a guard page.
    uint32_t required_space = 3 * page_size();
    remote_ptr<void> free_mem =
        t->vm()->find_free_memory(required_space,
                                  // Find free space after the patch site.
                                  t->vm()->mapping_of(from_end).map.start());

    remote_ptr<uint8_t> addr = (free_mem + page_size()).cast<uint8_t>();
    int64_t offset = addr - from_end;
    if ((int32_t)offset != offset) {
      LOG(debug) << "Can't find space close enough for the jump";
      return nullptr;
    }

    {
      AutoRemoteSyscalls remote(t);
      int prot = PROT_READ | PROT_EXEC;
      int flags = MAP_ANONYMOUS | MAP_FIXED | MAP_PRIVATE;
      auto ret = remote.infallible_mmap_syscall_if_alive(addr, page_size(), prot, flags, -1, 0);
      if (!ret) {
        /* Tracee died */
        return nullptr;
      }
      KernelMapping recorded(addr, addr + page_size(), string(),
                             KernelMapping::NO_DEVICE, KernelMapping::NO_INODE,
                             prot, flags);
      t->vm()->map(t, addr, page_size(), prot, flags, 0, string(),
                   KernelMapping::NO_DEVICE, KernelMapping::NO_INODE, nullptr,
                   &recorded);
      t->vm()->mapping_flags_of(addr) |= AddressSpace::Mapping::IS_PATCH_STUBS;
      t->trace_writer().write_mapped_region(t, recorded, recorded.fake_stat(),
                                            recorded.fsname(),
                                            vector<TraceRemoteFd>(),
                                            TraceWriter::PATCH_MAPPING);
    }

    pages.push_back(Monkeypatcher::ExtendedJumpPage(addr));
    page = &pages.back();
  }

  remote_ptr<uint8_t> jump_addr = page->addr + page->allocated;
  page->allocated += ExtendedJumpPatch::size;
  return jump_addr;
}

/**
 * Encode the standard movz|movk sequence for moving constant `v` into register `reg`
 */
static void encode_immediate_aarch64(std::vector<uint32_t> &buff,
                                     uint8_t reg, uint64_t v)
{
  DEBUG_ASSERT(reg < 31);
  const uint32_t movz_inst = 0xd2800000;
  const uint32_t movk_inst = 0xf2800000;
  uint32_t mov_inst = movz_inst;
  for (int lsl = 3; lsl >= 0; lsl--) {
    uint32_t bits = (v >> (lsl * 16)) & 0xffff;
    if (bits == 0 && !(lsl == 0 && mov_inst == movz_inst)) {
      // Skip zero bits unless it's the only instruction, i.e. v == 0
      continue;
    }
    // movz|movk x[reg], #bits, LSL #lsl
    buff.push_back(mov_inst | (uint32_t(lsl) << 21) | (bits << 5) | reg);
    mov_inst = movk_inst;
  }
}

/**
 * Encode the following assembly.
 *
 *    cmp     x8, 1024
 *    b.hi    .Lnosys
 *    movk    x8, preload_thread_locals >> 16, lsl 16
 *    stp     x15, x30, [x8, stub_scratch_2 - preload_thread_locals]
 *    movz    x30, #:abs_g3:_syscall_hook_trampoline
 *    movk    x30, #:abs_g2_nc:_syscall_hook_trampoline
 *    movk    x30, #:abs_g1_nc:_syscall_hook_trampoline
 *    movk    x30, #:abs_g0_nc:_syscall_hook_trampoline // Might be shorter depending on the address
 *    blr     x30
 *    ldp     x15, x30, [x15]
 *    b       .Lreturn
.Lbail:
 *    ldp     x15, x30, [x15]
 **   // Safe suffix starts here
.Lnosys:
 *    svc     0x0 // the test relies on invalid syscall triggering an event.
.Lreturn:
 *    b       syscall_return_address
 *    .long <syscall return address>
 *
 * And return the instruction index of `.Lreturn`.
 * The branch instruction following that label will not be encoded
 * since it depends on the address of this code.
 */
static uint32_t encode_extended_jump_aarch64(std::vector<uint32_t> &buff,
                                             uint64_t target, uint64_t return_addr,
                                             uint32_t *_retaddr_idx = nullptr)
{
  // cmp x8, 1024
  buff.push_back(0xf110011f);
  uint32_t b_hi_idx = buff.size();
  buff.push_back(0); // place holder
  // movk x8, preload_thread_locals >> 16, lsl 16
  buff.push_back(0xf2ae0028);
  // stp x15, x30, [x8, #104]
  buff.push_back(0xa906f90f);
  encode_immediate_aarch64(buff, 30, target);
  // blr x30
  buff.push_back(0xd63f03c0);
  // ldp x15, x30, [x15]
  buff.push_back(0xa94079ef);
  // b .+ 12
  buff.push_back(0x14000003);
  // ldp x15, x30, [x15]
  buff.push_back(0xa94079ef);
  buff.push_back(0xd4000001); // svc 0
  uint32_t ret_idx = buff.size();
  buff.push_back(0); // place holder
  // b.hi . + (ret_inst + 4 - .)
  buff[b_hi_idx] = 0x54000000 | ((ret_idx - 1 - b_hi_idx) << 5) | 0x8;

  uint32_t retaddr_idx = buff.size();
  if (_retaddr_idx)
    *_retaddr_idx = retaddr_idx;
  buff.resize(retaddr_idx + 2);
  memcpy(&buff[retaddr_idx], &return_addr, 8);
  return ret_idx;
}

// b and bl has a 26bit signed immediate in unit of 4 bytes
constexpr int32_t aarch64_b_max_offset = ((1 << 25) - 1) * 4;
constexpr int32_t aarch64_b_min_offset = (1 << 25) * -4;

static remote_ptr<uint8_t> allocate_extended_jump_aarch64(
    RecordTask* t, vector<Monkeypatcher::ExtendedJumpPage>& pages,
    remote_ptr<uint8_t> svc_ip, uint64_t to, std::vector<uint32_t> &inst_buff) {
  uint64_t return_addr = svc_ip.as_int() + 4;
  auto ret_idx = encode_extended_jump_aarch64(inst_buff, to, return_addr);
  auto total_patch_size = inst_buff.size() * 4;

  Monkeypatcher::ExtendedJumpPage* page = nullptr;

  // There are two jumps we need to worry about for the offset
  // (actually 3 since there's also the jump back after unpatching
  //  but the requirement for that is always more relaxed than the combination
  //  of these two),
  // the jump to the stub and the jump back.
  // The jump to the stub has offset `stub - syscall` and the jump back has offset
  // `syscall + 4 - (stub + ret_idx * 4)`
  // We need to make sure both are within the offset range so
  // * aarch64_b_min_offset <= stub - syscall <= aarch64_b_max_offset
  // * aarch64_b_min_offset <= syscall + 4 - (stub + ret_idx * 4) <= aarch64_b_max_offset
  // or
  // * aarch64_b_min_offset <= stub - syscall <= aarch64_b_max_offset
  // * -aarch64_b_max_offset + 4 - ret_idx * 4 <= stub - syscall <= -aarch64_b_min_offset + 4 - ret_idx * 4

  int64_t patch_offset_min = std::max(aarch64_b_min_offset,
                                      -aarch64_b_max_offset + 4 - int(ret_idx) * 4);
  int64_t patch_offset_max = std::min(aarch64_b_max_offset,
                                      -aarch64_b_min_offset + 4 - int(ret_idx) * 4);
  for (auto& p : pages) {
    remote_ptr<uint8_t> page_jump_start = p.addr + p.allocated;
    int64_t offset = page_jump_start - svc_ip;
    if (offset <= patch_offset_max && offset >= patch_offset_min &&
        p.allocated + total_patch_size <= page_size()) {
      page = &p;
      break;
    }
  }

  if (!page) {
    // We're looking for a gap of three pages --- one page to allocate and
    // a page on each side as a guard page.
    uint32_t required_space = 3 * page_size();
    remote_ptr<void> free_mem =
        t->vm()->find_free_memory(required_space,
                                  // Find free space after the patch site.
                                  t->vm()->mapping_of(svc_ip).map.start());

    remote_ptr<uint8_t> addr = (free_mem + page_size()).cast<uint8_t>();
    int64_t offset = addr - svc_ip;
    if (offset > patch_offset_max || offset < patch_offset_min) {
      LOG(debug) << "Can't find space close enough for the jump";
      return nullptr;
    }

    {
      AutoRemoteSyscalls remote(t);
      int prot = PROT_READ | PROT_EXEC;
      int flags = MAP_ANONYMOUS | MAP_FIXED | MAP_PRIVATE;
      auto ret = remote.infallible_mmap_syscall_if_alive(addr, page_size(), prot, flags, -1, 0);
      if (!ret) {
        /* Tracee died */
        return nullptr;
      }
      KernelMapping recorded(addr, addr + page_size(), string(),
                             KernelMapping::NO_DEVICE, KernelMapping::NO_INODE,
                             prot, flags);
      t->vm()->map(t, addr, page_size(), prot, flags, 0, string(),
                   KernelMapping::NO_DEVICE, KernelMapping::NO_INODE, nullptr,
                   &recorded);
      t->vm()->mapping_flags_of(addr) |= AddressSpace::Mapping::IS_PATCH_STUBS;
      t->trace_writer().write_mapped_region(t, recorded, recorded.fake_stat(),
                                            recorded.fsname(),
                                            vector<TraceRemoteFd>(),
                                            TraceWriter::PATCH_MAPPING);
    }

    pages.push_back(Monkeypatcher::ExtendedJumpPage(addr));
    page = &pages.back();
  }

  remote_ptr<uint8_t> jump_addr = page->addr + page->allocated;

  const uint64_t reverse_jump_addr = jump_addr.as_int() + ret_idx * 4;
  const int64_t reverse_offset = int64_t(return_addr - reverse_jump_addr);
  const uint32_t offset_imm26 = (reverse_offset >> 2) & 0x03ffffff;
  inst_buff[ret_idx] = 0x14000000 | offset_imm26;

  page->allocated += total_patch_size;

  return jump_addr;
}

Monkeypatcher::patched_syscall *Monkeypatcher::find_jump_stub(remote_code_ptr ip, bool include_safearea) {
  remote_ptr<uint8_t> pp = ip.to_data_ptr<uint8_t>();
  auto it = syscallbuf_stubs_by_extended_patch.upper_bound(pp);
  if (it == syscallbuf_stubs_by_extended_patch.begin()) {
    return nullptr;
  }
  --it;
  auto begin = it->first;
  patched_syscall *ps = &syscall_stub_list[it->second];
  auto end = begin + ps->size;
  if (!include_safearea) {
    begin += ps->safe_prefix;
    end -= ps->safe_suffix;
  }
  return begin <= pp && pp < end ? ps : nullptr;
}

Monkeypatcher::patched_syscall *Monkeypatcher::find_syscall_patch(remote_code_ptr ip) {
  remote_ptr<uint8_t> pp = ip.to_data_ptr<uint8_t>();
  auto it = syscallbuf_stubs_by_patch_addr.upper_bound(pp);
  if (it == syscallbuf_stubs_by_patch_addr.begin()) {
    return nullptr;
  }
  --it;
  auto begin = it->first;
  patched_syscall *ps = &syscall_stub_list[it->second];
  auto end = begin + ps->hook->patch_region_length;
  return begin <= pp && pp < end ? ps : nullptr;
}

remote_code_ptr Monkeypatcher::get_jump_stub_exit_breakpoint(remote_code_ptr ip,
                                                             RecordTask *t) {
  if (t->arch() != aarch64) {
    return nullptr;
  }
  remote_ptr<uint8_t> pp = ip.to_data_ptr<uint8_t>();
  auto it = syscallbuf_stubs_by_extended_patch.upper_bound(pp);
  if (it == syscallbuf_stubs_by_extended_patch.begin()) {
    return nullptr;
  }
  --it;
  patched_syscall *ps = &syscall_stub_list[it->second];
  auto bp = it->first + ps->size - ps->safe_suffix;
  if (pp == bp - 4 || pp == bp - 8 || pp == bp - 12) {
    return remote_code_ptr((it->first + ps->size - 12).as_int());
  }
  return nullptr;
}

template <typename ExtendedJumpPatch>
uint64_t get_safe_suffix_length();

/* These need to match the size of the post-stack-restore region in assembly_templates.py */
template <>
uint64_t get_safe_suffix_length<X64SyscallStubExtendedJump>() {
  return 8 + 8 + 6 + 20 + 2;
}

template <>
uint64_t get_safe_suffix_length<X86SyscallStubExtendedJump>() {
  return 2 + 20 + 1 + 4;
}


static void fill_with_x86_nops(uint8_t *buf, size_t len) {
  for (size_t i = 0; i < len;) {
    switch (len - i) {
      case 1: buf[i] = 0x90; return;
      case 2: buf[i] = 0x60; buf[i+1] = 0x90; return;
      case 3: buf[i] = 0x0f; buf[i+1] = 0x1f; buf[i+2] = 0x00; return;
      case 4: buf[i] = 0x0f; buf[i+1] = 0x1f; buf[i+2] = 0x40; buf[i+3] = 0x00; break;
      case 5: buf[i] = 0x0f; buf[i+1] = 0x1f; buf[i+2] = 0x44;
              buf[i+3] = 0x00; buf[i+4] = 0x00; return;
      case 6: buf[i] = 0x66; buf[i+1] = 0x0f; buf[i+2] = 0x1f;
              buf[i+3] = 0x44; buf[i+4] = 0x00; buf[i+5] = 0x00; return;
      case 7: buf[i] = 0x0f; buf[i+1] = 0x1f; buf[i+2] = 0x80;
              buf[i+3] = 0x00; buf[i+4] = 0x00; buf[i+5] = 0x00;
              buf[i+6] = 0x00; return;
      case 8: buf[i] = 0x0f; buf[i+1] = 0x1f; buf[i+2] = 0x84;
              buf[i+3] = 0x00; buf[i+4] = 0x00; buf[i+5] = 0x00;
              buf[i+6] = 0x00; buf[i+7] = 0x00; return;
      default:
      case 9:
        buf[i] = 0x66; buf[i+1] = 0x0f; buf[i+2] = 0x1f;
        buf[i+3] = 0x84; buf[i+4] = 0x00; buf[i+5] = 0x00;
        buf[i+6] = 0x00; buf[i+7] = 0x00; buf[i+8] = 0x00;
        i += 9; continue;
    }
  }
}

/**
 * Some functions make system calls while storing local variables in memory
 * below the stack pointer. We need to decrement the stack pointer by
 * some "safety zone" amount to get clear of those variables before we make
 * a call instruction. So, we allocate a stub per patched callsite, and jump
 * from the callsite to the stub. The stub decrements the stack pointer,
 * calls the appropriate syscall hook function, reincrements the stack pointer,
 * and jumps back to immediately after the patched callsite.
 *
 * It's important that gdb stack traces work while a thread is stopped in the
 * syscallbuf code. To ensure that the above manipulations don't foil gdb's
 * stack walking code, we add CFI data to all the stubs. To ease that, the
 * stubs are written in assembly and linked into the preload library.
 *
 * On x86-64 with ASLR, we need to be able to patch a call to a stub from
 * sites more than 2^31 bytes away. We only have space for a 5-byte jump
 * instruction. So, we allocate "extender pages" --- pages of memory within
 * 2GB of the patch site, that contain the stub code. We don't really need this
 * on x86, but we do it there too for consistency.
 *
 * If fake_syscall_number > 0 then we'll ensure AX is set to that number
 * by the stub code.
 */
template <typename JumpPatch, typename ExtendedJumpPatch, typename FakeSyscallExtendedJumpPatch>
static bool patch_syscall_with_hook_x86ish(Monkeypatcher& patcher,
                                           RecordTask* t,
                                           const syscall_patch_hook& hook,
                                           size_t instruction_length,
                                           uint32_t fake_syscall_number) {
  uint8_t jump_patch[instruction_length + hook.patch_region_length];
  // We're patching in a relative jump, so we need to compute the offset from
  // the end of the jump to our actual destination.
  auto jump_patch_start = t->regs().ip().to_data_ptr<uint8_t>();
  auto jump_patch_end = jump_patch_start + JumpPatch::size;
  auto return_addr = t->regs().ip().to_data_ptr<uint8_t>().as_int() +
                     instruction_length +
                     hook.patch_region_length;
  if ((hook.flags & PATCH_SYSCALL_INSTRUCTION_IS_LAST)) {
    auto adjust = hook.patch_region_length + instruction_length;
    jump_patch_start -= adjust;
    jump_patch_end -= adjust;
    return_addr -= adjust;
  }

  remote_ptr<uint8_t> extended_jump_start;
  if (fake_syscall_number) {
    extended_jump_start = allocate_extended_jump_x86ish<FakeSyscallExtendedJumpPatch>(
        t, patcher.extended_jump_pages, jump_patch_end);
  } else {
    extended_jump_start = allocate_extended_jump_x86ish<ExtendedJumpPatch>(
          t, patcher.extended_jump_pages, jump_patch_end);
  }
  if (extended_jump_start.is_null()) {
    return false;
  }

  uint8_t stub[20];
  memset(stub, 0x90, sizeof(stub));
  if (!(hook.flags & PATCH_SYSCALL_INSTRUCTION_IS_LAST)) {
    memcpy(stub, hook.patch_region_bytes, hook.patch_region_length);
    fill_with_x86_nops(stub + hook.patch_region_length, sizeof(stub) - hook.patch_region_length);
  }

  uint16_t safe_suffix = get_safe_suffix_length<ExtendedJumpPatch>(); // Everything starting from the syscall instruction
  if (fake_syscall_number) {
    uint8_t stub_patch[FakeSyscallExtendedJumpPatch::size];
    substitute_extended_jump<FakeSyscallExtendedJumpPatch>(stub_patch,
                                                extended_jump_start.as_int(),
                                                return_addr,
                                                hook.hook_address,
                                                fake_syscall_number,
                                                stub);
    write_and_record_bytes(t, extended_jump_start, stub_patch);

    patcher.syscall_stub_list.push_back({ &hook, jump_patch_start, extended_jump_start, FakeSyscallExtendedJumpPatch::size, 0, safe_suffix });
    patcher.syscallbuf_stubs_by_extended_patch[extended_jump_start] = patcher.syscall_stub_list.size() - 1;
    patcher.syscallbuf_stubs_by_patch_addr[jump_patch_start] = patcher.syscall_stub_list.size() - 1;
  } else {
    uint8_t stub_patch[ExtendedJumpPatch::size];
    substitute_extended_jump<ExtendedJumpPatch>(stub_patch,
                                                extended_jump_start.as_int(),
                                                return_addr,
                                                hook.hook_address,
                                                0,
                                                stub);
    write_and_record_bytes(t, extended_jump_start, stub_patch);

    patcher.syscall_stub_list.push_back({ &hook, jump_patch_start, extended_jump_start, ExtendedJumpPatch::size, 0, safe_suffix });
    patcher.syscallbuf_stubs_by_extended_patch[extended_jump_start] = patcher.syscall_stub_list.size() - 1;
    patcher.syscallbuf_stubs_by_patch_addr[jump_patch_start] = patcher.syscall_stub_list.size() - 1;
  }

  intptr_t jump_offset = extended_jump_start - jump_patch_end;
  int32_t jump_offset32 = (int32_t)jump_offset;
  ASSERT(t, jump_offset32 == jump_offset)
      << "allocate_extended_jump_x86ish didn't work";

  // pad with NOPs to the next instruction
  static const uint8_t NOP = 0x90;
  memset(jump_patch, NOP, sizeof(jump_patch));
  JumpPatch::substitute(jump_patch, jump_offset32);
  bool ok = true;
  write_and_record_bytes(t, jump_patch_start, sizeof(jump_patch), jump_patch, &ok);
  if (!ok) {
    LOG(warn) << "Couldn't write patch; errno=" << errno;
  }
  return ok;
}

template <>
bool patch_syscall_with_hook_arch<X86Arch>(Monkeypatcher& patcher,
                                           RecordTask* t,
                                           const syscall_patch_hook& hook,
                                           size_t instruction_length,
                                           uint32_t fake_syscall_number) {
  return patch_syscall_with_hook_x86ish<X86SysenterVsyscallSyscallHook,
                                        X86SyscallStubExtendedJump,
                                        X86TrapInstructionStubExtendedJump>(patcher, t,
                                                                            hook, instruction_length,
                                                                            fake_syscall_number);
}

template <>
bool patch_syscall_with_hook_arch<X64Arch>(Monkeypatcher& patcher,
                                           RecordTask* t,
                                           const syscall_patch_hook& hook,
                                           size_t instruction_length,
                                           uint32_t fake_syscall_number) {
  return patch_syscall_with_hook_x86ish<X64JumpMonkeypatch,
                                        X64SyscallStubExtendedJump,
                                        X64TrapInstructionStubExtendedJump>(patcher, t,
                                                                            hook, instruction_length,
                                                                            fake_syscall_number);
}

template <>
bool patch_syscall_with_hook_arch<ARM64Arch>(Monkeypatcher& patcher,
                                             RecordTask *t,
                                             const syscall_patch_hook &hook,
                                             size_t,
                                             uint32_t) {
  Registers r = t->regs();
  remote_ptr<uint8_t> svc_ip = r.ip().to_data_ptr<uint8_t>();
  std::vector<uint32_t> inst_buff;

  remote_ptr<uint8_t> extended_jump_start =
    allocate_extended_jump_aarch64(
      t, patcher.extended_jump_pages, svc_ip, hook.hook_address, inst_buff);
  if (extended_jump_start.is_null()) {
    return false;
  }
  LOG(debug) << "Allocated stub size " << inst_buff.size() * sizeof(uint32_t)
             << " bytes at " << extended_jump_start << " for syscall at "
             << svc_ip;

  auto total_patch_size = inst_buff.size() * 4;
  write_and_record_bytes(t, extended_jump_start, total_patch_size, &inst_buff[0]);

  patcher.syscall_stub_list.push_back({
    &hook, svc_ip, extended_jump_start, total_patch_size,
    /**
     * safe_prefix:
     * We have not modified any registers yet in the first two instructions.
     * More importantly, we may bail out and return to user code without
     * hitting the breakpoint in syscallbuf
     */
    2 * 4,
    /**
     * safe_suffix:
     * The safe suffix are all instructions that are no longer using syscallbuf
     * private stack memory. On aarch64, that is the bail path svc instruction
     * and the final jump instruction (including the 8 byte return address).
     * See the detailed extended jump patch assembly above for details.
     * Note that the stack restore instructions also occurr on the syscallbuf
     * return path, but are not considered part of the safe suffix, since they
     * still rely on the syscallbuf stack memory to function properly.
     */
    2 * 4 + 8
  });
  patcher.syscallbuf_stubs_by_extended_patch[extended_jump_start] = patcher.syscall_stub_list.size() - 1;
  patcher.syscallbuf_stubs_by_patch_addr[svc_ip] = patcher.syscall_stub_list.size() - 1;

  intptr_t jump_offset = extended_jump_start - svc_ip;
  ASSERT(t, jump_offset <= aarch64_b_max_offset && jump_offset >= aarch64_b_min_offset)
      << "allocate_extended_jump_aarch64 didn't work";

  const uint32_t offset_imm26 = (jump_offset >> 2) & 0x03ffffff;
  const uint32_t b_inst = 0x14000000 | offset_imm26;
  bool ok = true;
  write_and_record_bytes(t, svc_ip, 4, &b_inst, &ok);
  if (!ok) {
    LOG(warn) << "Couldn't write patch; errno=" << errno;
  }
  return ok;
}


static bool patch_syscall_with_hook(Monkeypatcher& patcher, RecordTask* t,
                                    const syscall_patch_hook& hook,
                                    size_t instruction_length,
                                    uint32_t fake_syscall_number) {
  RR_ARCH_FUNCTION(patch_syscall_with_hook_arch, t->arch(), patcher, t, hook,
                        instruction_length, fake_syscall_number);
}

template <typename ReplacementPatch>
static void substitute_replacement_patch(uint8_t *buffer, uint64_t patch_addr,
                                     uint64_t jmp_target);

template <>
void substitute_replacement_patch<X64SyscallStubRestore>(uint8_t *buffer, uint64_t patch_addr,
                                  uint64_t jmp_target) {
  (void)patch_addr;
  X64SyscallStubRestore::substitute(buffer, jmp_target);
}

template <>
void substitute_replacement_patch<X86SyscallStubRestore>(uint8_t *buffer, uint64_t patch_addr,
                                  uint64_t jmp_target) {
  int64_t offset =
      jmp_target -
      (patch_addr + X86SyscallStubRestore::trampoline_relative_addr_end);
  // An offset that appears to be > 2GB is OK here, since EIP will just
  // wrap around.
  X86SyscallStubRestore::substitute(buffer, (uint32_t)offset);
}

template <typename ExtendedJumpPatch, typename FakeSyscallExtendedJumpPatch, typename ReplacementPatch>
static void unpatch_extended_jumps(Monkeypatcher& patcher,
                                   Task* t) {
  static_assert(ExtendedJumpPatch::size < FakeSyscallExtendedJumpPatch::size);
  for (auto &patch : patcher.syscall_stub_list) {
    const syscall_patch_hook &hook = *patch.hook;
    ASSERT(t, patch.size <= FakeSyscallExtendedJumpPatch::size);
    uint8_t bytes[FakeSyscallExtendedJumpPatch::size];
    uint64_t return_addr = patch.patch_addr.as_int() + hook.patch_region_length;
    std::vector<uint8_t> syscall = rr::syscall_instruction(t->arch());

    // Replace with
    //  extended_jump:
    //    <syscall> (unless PATCH_SYSCALL_INSTRUCTION_IS_LAST)
    //    <original bytes>
    //    <syscall> (if PATCH_SYSCALL_INSTRUCTION_IS_LAST)
    //    jmp *(return_addr)
    // As long as there are not relative branches or anything, this should
    // always be correct.
    ASSERT(t, hook.patch_region_length + ReplacementPatch::size + syscall.size() <
              ExtendedJumpPatch::size);
    uint8_t *ptr = bytes;
    if (hook.flags & PATCH_SYSCALL_INSTRUCTION_IS_LAST) {
      memcpy(ptr, syscall.data(), syscall.size());
      ptr += syscall.size();
      memcpy(ptr, hook.patch_region_bytes, hook.patch_region_length);
      substitute_replacement_patch<ReplacementPatch>(ptr,
        patch.stub_addr.as_int()+(ptr-bytes), return_addr);
      t->write_bytes_helper(patch.stub_addr, sizeof(bytes), bytes);
    } else {
      // We already have a copy of the replaced bytes in place - all we need to
      // to is to nop out the preceeding instructions
      uint64_t nop_area_size = ExtendedJumpPatch::size - get_safe_suffix_length<ExtendedJumpPatch>();
      memset(ptr, 0x90, nop_area_size);
      t->write_bytes_helper(patch.stub_addr, nop_area_size, bytes);
    }
  }
}

template <typename Arch>
static void unpatch_syscalls_arch(Monkeypatcher &patcher, Task *t);

template <>
void unpatch_syscalls_arch<X86Arch>(Monkeypatcher &patcher, Task *t) {
  // There is no 32-bit equivalent to X64TrapInstructionStubExtendedJump.
  // We just pass the X64TrapInstructionStubExtendedJump; its length
  // will never match any jump stub for 32-bit.
  return unpatch_extended_jumps<X86SyscallStubExtendedJump,
                                X64TrapInstructionStubExtendedJump,
                                X86SyscallStubRestore>(patcher, t);
}

template <>
void unpatch_syscalls_arch<X64Arch>(Monkeypatcher &patcher, Task *t) {
  return unpatch_extended_jumps<X64SyscallStubExtendedJump,
                                X64TrapInstructionStubExtendedJump,
                                X64SyscallStubRestore>(patcher, t);
}

template <>
void unpatch_syscalls_arch<ARM64Arch>(Monkeypatcher &patcher, Task *t) {
  for (auto patch : patcher.syscall_stub_list) {
    const syscall_patch_hook &hook = *patch.hook;
    std::vector<uint32_t> hook_prefix;
    uint32_t prefix_ninst;
    encode_extended_jump_aarch64(hook_prefix, hook.hook_address, 0, &prefix_ninst);
    uint32_t prefix_size = prefix_ninst * 4;
    DEBUG_ASSERT(prefix_size <= 13 * 4);
    ASSERT(t, patch.size >= prefix_size + 8);
    uint8_t bytes[15 * 4];
    t->read_bytes_helper(patch.stub_addr, prefix_size + 8, bytes);
    // 3rd last instruction is the one jumping back and it won't match
    if (memcmp(&hook_prefix[0], bytes, prefix_size - 3 * 4) != 0) {
      ASSERT(t, false) << "Failed to match extended jump patch at " << patch.stub_addr;
      return;
    }

    uint64_t return_addr;
    memcpy(&return_addr, &bytes[prefix_size], 8);

    uint32_t svc_inst = 0xd4000001;
    memcpy(bytes, &svc_inst, 4);

    uint64_t reverse_jump_addr = patch.stub_addr.as_int() + 4;
    int64_t reverse_offset = int64_t(return_addr - reverse_jump_addr);
    ASSERT(t, reverse_offset <= aarch64_b_max_offset &&
           reverse_offset >= aarch64_b_min_offset)
      << "Cannot encode b instruction to jump back";
    uint32_t offset_imm26 = (reverse_offset >> 2) & 0x03ffffff;
    uint32_t binst = 0x14000000 | offset_imm26;
    memcpy(&bytes[4], &binst, 4);

    t->write_bytes_helper(patch.stub_addr, 4 * 2, bytes);
  }
}

void Monkeypatcher::unpatch_syscalls_in(Task *t) {
  RR_ARCH_FUNCTION(unpatch_syscalls_arch, t->arch(), *this, t);
}

static string bytes_to_string(uint8_t* bytes, size_t size) {
  stringstream ss;
  for (size_t i = 0; i < size; ++i) {
    if (i > 0) {
      ss << ' ';
    }
    ss << HEX(bytes[i]);
  }
  return ss.str();
}

static bool task_safe_for_syscall_patching(RecordTask* t, remote_code_ptr start,
                                           remote_code_ptr end) {
  if (!t->is_running()) {
    remote_code_ptr ip = t->ip();
    if (start <= ip && ip < end) {
      return false;
    }
  }
  for (auto& e : t->pending_events) {
    if (e.is_syscall_event()) {
      remote_code_ptr ip = e.Syscall().regs.ip();
      if (start <= ip && ip < end) {
        return false;
      }
    }
  }
  return true;
}

static bool safe_for_syscall_patching(remote_code_ptr start,
                                      remote_code_ptr end,
                                      RecordTask* exclude) {
  for (auto& p : exclude->session().tasks()) {
    RecordTask* rt = static_cast<RecordTask*>(p.second);
    if (rt != exclude && !task_safe_for_syscall_patching(rt, start, end)) {
      return false;
    }
  }
  return true;
}

bool Monkeypatcher::try_patch_vsyscall_caller(RecordTask* t, remote_code_ptr ret_addr)
{
  // Emit FLUSH_SYSCALLBUF if there's one pending.
  // We want our mmap records to be associated with the next (PATCH_SYSCALL)
  // event, not a FLUSH_SYSCALLBUF event.
  t->maybe_flush_syscallbuf();

  uint8_t bytes[X64VSyscallEntry::size];
  remote_ptr<uint8_t> patch_start = ret_addr.to_data_ptr<uint8_t>() - sizeof(bytes);
  size_t bytes_count = t->read_bytes_fallible(patch_start, sizeof(bytes), bytes);
  if (bytes_count < sizeof(bytes)) {
    return false;
  }
  uint32_t target_addr = 0;
  if (!X64VSyscallEntry::match(bytes, &target_addr)) {
    return false;
  }
  uint64_t target_addr_sext = (uint64_t)(int32_t)target_addr;
  int syscallno = 0;
  switch (target_addr_sext) {
    case 0xffffffffff600000:
      syscallno = X64Arch::gettimeofday;
      break;
    case 0xffffffffff600400:
      syscallno = X64Arch::time;
      break;
    case 0xffffffffff600800:
      syscallno = X64Arch::getcpu;
      break;
    default:
      return false;
  }
  X64VSyscallReplacement::substitute(bytes, syscallno);
  write_and_record_bytes(t, patch_start, bytes);
  LOG(debug) << "monkeypatched vsyscall caller at " << patch_start;
  return true;
}

const syscall_patch_hook* Monkeypatcher::find_syscall_hook(RecordTask* t,
                                                           remote_code_ptr ip,
                                                           bool allow_deferred_patching,
                                                           bool entering_syscall,
                                                           size_t instruction_length) {
  /* we need to inspect this many bytes before the start of the instruction,
     to find every short jump that might land after it. Conservative. */
  static const intptr_t LOOK_BACK = 0x80;
  /* we need to inspect this many bytes after the start of the instruction,
     to find every short jump that might land after it into the patch area.
     Conservative. */
  static const intptr_t LOOK_FORWARD = 15 + 15 + 0x80;
  uint8_t bytes[LOOK_BACK + LOOK_FORWARD];
  memset(bytes, 0, sizeof(bytes));

  // Split reading the code into separate reads for each page, so that if we can't read
  // from one page, we still get the data from the other page.
  ASSERT(t, sizeof(bytes) < page_size());
  remote_ptr<uint8_t> code_start = ip.to_data_ptr<uint8_t>() - LOOK_BACK;
  size_t buf_valid_start_offset = 0;
  size_t buf_valid_end_offset = sizeof(bytes);
  ssize_t first_page_bytes = min<size_t>(ceil_page_size(code_start) - code_start, sizeof(bytes));
  if (t->read_bytes_fallible(code_start, first_page_bytes, bytes) < first_page_bytes) {
    buf_valid_start_offset = first_page_bytes;
  }
  if (first_page_bytes < (ssize_t)sizeof(bytes)) {
    if (t->read_bytes_fallible(code_start + first_page_bytes, sizeof(bytes) - first_page_bytes,
                               bytes + first_page_bytes) < (ssize_t)sizeof(bytes) - first_page_bytes) {
      buf_valid_end_offset = first_page_bytes;
    }
  }

  if (buf_valid_start_offset > LOOK_BACK ||
      buf_valid_end_offset < LOOK_BACK + instruction_length) {
    ASSERT(t, false)
      << "Can't read memory containing patchable instruction, why are we trying this?";
  }

  uint8_t* following_bytes = &bytes[LOOK_BACK + instruction_length];
  size_t following_bytes_count = buf_valid_end_offset - (LOOK_BACK + instruction_length);
  size_t preceding_bytes_count = LOOK_BACK - buf_valid_start_offset;

  for (const auto& hook : syscall_hooks) {
    bool matches_hook = false;
    if ((!(hook.flags & PATCH_SYSCALL_INSTRUCTION_IS_LAST) &&
         following_bytes_count >= hook.patch_region_length &&
         memcmp(following_bytes, hook.patch_region_bytes,
                hook.patch_region_length) == 0)) {
      matches_hook = true;
    } else if ((hook.flags & PATCH_SYSCALL_INSTRUCTION_IS_LAST) &&
               allow_deferred_patching &&
               hook.patch_region_length <= preceding_bytes_count &&
               memcmp(bytes + LOOK_BACK - hook.patch_region_length,
                      hook.patch_region_bytes,
                      hook.patch_region_length) == 0) {
      if (entering_syscall) {
        // A patch that uses bytes before the syscall can't be done when
        // entering the syscall, it must be done when exiting. So set a flag on
        // the Task that tells us to come back later.
        t->retry_syscall_patching = true;
        LOG(debug) << "Deferring syscall patching at " << ip << " in " << t
                   << " until syscall exit.";
        return nullptr;
      }
      matches_hook = true;
    }

    if (!matches_hook) {
      continue;
    }

    // Search for a following short-jump instruction that targets an
    // instruction
    // after the syscall. False positives are OK.
    // glibc-2.23.1-8.fc24.x86_64's __clock_nanosleep needs this.
    bool found_potential_interfering_branch = false;
    for (size_t i = buf_valid_start_offset; i + 2 <= buf_valid_end_offset; ++i) {
      uint8_t b = bytes[i];
      // Check for short conditional or unconditional jump
      if (b == 0xeb || (b >= 0x70 && b < 0x80)) {
        int offset_from_instruction_end = (int)i + 2 + (int8_t)bytes[i + 1] -
            (LOOK_BACK + instruction_length);
        if ((hook.flags & PATCH_IS_MULTIPLE_INSTRUCTIONS)
                ? (offset_from_instruction_end >= 0 && offset_from_instruction_end < hook.patch_region_length)
                : offset_from_instruction_end == 0) {
          LOG(debug) << "Found potential interfering branch at "
                      << ip.to_data_ptr<uint8_t>() - LOOK_BACK + i;
          // We can't patch this because it would jump straight back into
          // the middle of our patch code.
          found_potential_interfering_branch = true;
          break;
        }
      }
    }

    if (!found_potential_interfering_branch) {
      remote_code_ptr start_range, end_range;
      if (hook.flags & PATCH_SYSCALL_INSTRUCTION_IS_LAST) {
        start_range = ip - hook.patch_region_length;
        end_range = ip + instruction_length;
      } else {
        start_range = ip;
        end_range = ip + instruction_length + hook.patch_region_length;
      }
      if (!safe_for_syscall_patching(start_range, end_range, t)) {
        LOG(debug)
            << "Temporarily declining to patch syscall at " << ip
            << " because a different task has its ip in the patched range";
        return nullptr;
      }
      LOG(debug) << "Trying to patch bytes "
                 << bytes_to_string(
                      following_bytes,
                      min<size_t>(following_bytes_count,
                          sizeof(syscall_patch_hook::patch_region_bytes)));

      return &hook;
    }
  }

  LOG(debug) << "Failed to find a syscall hook for bytes "
             << bytes_to_string(
                    following_bytes,
                    min<size_t>(following_bytes_count,
                        sizeof(syscall_patch_hook::patch_region_bytes)));

  return nullptr;
}

// Syscalls can be patched either on entry or exit. For most syscall
// instruction code patterns we can steal bytes after the syscall instruction
// and thus we patch on entry, but some patterns require using bytes from
// before the syscall instruction itself and thus can only be patched on exit.
// The `entering_syscall` flag tells us whether or not we're at syscall entry.
// If we are, and we find a pattern that can only be patched at exit, we'll
// set a flag on the RecordTask telling it to try again after syscall exit.
bool Monkeypatcher::try_patch_syscall_x86ish(RecordTask* t, bool entering_syscall,
                                             SupportedArch arch) {
  Registers r = t->regs();
  remote_code_ptr ip = r.ip();

  ASSERT(t, is_x86ish(arch)) << "Unsupported architecture";

  size_t instruction_length = rr::syscall_instruction_length(arch);
  const syscall_patch_hook* hook_ptr = find_syscall_hook(t, ip - instruction_length,
      true, entering_syscall, instruction_length);
  bool success = false;
  intptr_t syscallno = r.original_syscallno();
  if (hook_ptr) {
    // Get out of executing the current syscall before we patch it.
    if (entering_syscall && !t->exit_syscall_and_prepare_restart()) {
      return false;
    }

    LOG(debug) << "Patching syscall at " << ip << " syscall "
               << syscall_name(syscallno, t->arch()) << " tid " << t->tid;

    success = patch_syscall_with_hook(*this, t, *hook_ptr, instruction_length, 0);
    if (!success && entering_syscall) {
      // Need to reenter the syscall to undo exit_syscall_and_prepare_restart
      t->enter_syscall();
    }
  }

  if (!success) {
    if (!t->retry_syscall_patching) {
      LOG(debug) << "Failed to patch syscall at " << ip << " syscall "
                 << syscall_name(syscallno, t->arch()) << " tid " << t->tid;
      tried_to_patch_syscall_addresses.insert(ip);
    }
    return false;
  }

  return true;
}

bool Monkeypatcher::try_patch_syscall_aarch64(RecordTask* t, bool entering_syscall) {
  Registers r = t->regs();
  remote_code_ptr ip = r.ip() - 4;

  uint32_t inst[2] = {0, 0};
  size_t bytes_count = t->read_bytes_fallible(ip.to_data_ptr<uint8_t>() - 4, 8, &inst);
  if (bytes_count < sizeof(inst) || inst[1] != 0xd4000001) {
    LOG(debug) << "Declining to patch syscall at "
               << ip << " for unexpected instruction";
    tried_to_patch_syscall_addresses.insert(ip);
    return false;
  }
  // mov x8, 0xdc
  if (inst[0] == 0xd2801b88) {
    // Clone may either cause the new and the old process to share stack (vfork)
    // or replacing the stack (pthread_create)
    // and requires special handling on the caller.
    // Our syscall hook cannot do that so this would have to be a raw syscall.
    // We can handle this at runtime but if we know the call is definitely
    // a clone we can avoid patching it here.
    LOG(debug) << "Declining to patch clone syscall at " << ip;
    tried_to_patch_syscall_addresses.insert(ip);
    return false;
  }

  ASSERT(t, (syscall_hooks.size() == 1 && syscall_hooks[0].patch_region_length == 4 &&
             memcmp(syscall_hooks[0].patch_region_bytes, &inst[1], 4) == 0))
    << "Unknown syscall hook";

  if (!safe_for_syscall_patching(ip, ip + 4, t)) {
    LOG(debug)
      << "Temporarily declining to patch syscall at " << ip
      << " because a different task has its ip in the patched range";
    return false;
  }

  // Get out of executing the current syscall before we patch it.
  if (entering_syscall && !t->exit_syscall_and_prepare_restart()) {
    return false;
  }

  LOG(debug) << "Patching syscall at " << ip << " syscall "
             << syscall_name(r.original_syscallno(), aarch64) << " tid " << t->tid;

  auto success = patch_syscall_with_hook(*this, t, syscall_hooks[0], 4, 0);
  if (!success && entering_syscall) {
    // Need to reenter the syscall to undo exit_syscall_and_prepare_restart
    t->enter_syscall();
  }

  if (!success) {
    LOG(debug) << "Failed to patch syscall at " << ip << " syscall "
               << syscall_name(r.original_syscallno(), aarch64) << " tid " << t->tid;
    tried_to_patch_syscall_addresses.insert(ip);
    return false;
  }

  return true;
}

bool Monkeypatcher::try_patch_syscall(RecordTask* t, bool entering_syscall) {
  if (syscall_hooks.empty()) {
    // Syscall hooks not set up yet. Don't spew warnings, and don't
    // fill tried_to_patch_syscall_addresses with addresses that we might be
    // able to patch later.
    return false;
  }
  if (t->emulated_ptracer) {
    // Syscall patching can confuse ptracers, which may be surprised to see
    // a syscall instruction at the current IP but then when running
    // forwards, that the syscall occurs deep in the preload library instead.
    return false;
  }
  if (t->is_in_traced_syscall()) {
    // Never try to patch the traced-syscall in our preload library!
    return false;
  }

  Registers r = t->regs();
  remote_code_ptr ip = r.ip();
  // We should not get here for untraced syscalls or anything else from the rr page.
  // These should be normally prevented by our seccomp filter
  // and in the case of syscalls interrupted by signals,
  // the check for the syscall restart should prevent us from reaching here.
  DEBUG_ASSERT(ip.to_data_ptr<void>() < AddressSpace::rr_page_start() ||
               ip.to_data_ptr<void>() >= AddressSpace::rr_page_end());
  if (tried_to_patch_syscall_addresses.count(ip) || is_jump_stub_instruction(ip, true)) {
    return false;
  }

  // We could examine the current syscall number and if it's not one that
  // we support syscall buffering for, refuse to patch the syscall instruction.
  // This would, on the face of it, reduce overhead since patching the
  // instruction just means a useless trip through the syscall buffering logic.
  // However, it actually wouldn't help much since we'd still do a switch
  // on the syscall number in this function instead, and due to context
  // switching costs any overhead saved would be insignificant.
  // Also, implementing that would require keeping a buffered-syscalls
  // list in sync with the preload code, which is unnecessary complexity.

  SupportedArch arch;
  if (!get_syscall_instruction_arch(
          t, ip.decrement_by_syscall_insn_length(t->arch()), &arch) ||
      arch != t->arch()) {
    LOG(debug) << "Declining to patch cross-architecture syscall at " << ip;
    tried_to_patch_syscall_addresses.insert(ip);
    return false;
  }

  // Emit FLUSH_SYSCALLBUF if there's one pending.
  // We want our mmap records to be associated with the next (PATCH_SYSCALL)
  // event, not a FLUSH_SYSCALLBUF event.
  t->maybe_flush_syscallbuf();

  if (arch == aarch64) {
    return try_patch_syscall_aarch64(t, entering_syscall);
  }
  return try_patch_syscall_x86ish(t, entering_syscall, arch);
}

bool Monkeypatcher::try_patch_trapping_instruction(RecordTask* t, size_t instruction_length) {
  if (syscall_hooks.empty()) {
    // Syscall hooks not set up yet. Don't spew warnings, and don't
    // fill tried_to_patch_syscall_addresses with addresses that we might be
    // able to patch later.
    return false;
  }
  if (t->emulated_ptracer) {
    // Patching can confuse ptracers.
    return false;
  }

  Registers r = t->regs();
  remote_code_ptr ip = r.ip();
  if (tried_to_patch_syscall_addresses.count(ip + instruction_length)) {
    return false;
  }

  // Emit FLUSH_SYSCALLBUF if there's one pending.
  // We want our mmap records to be associated with the next (PATCH_SYSCALL)
  // event, not a FLUSH_SYSCALLBUF event.
  t->maybe_flush_syscallbuf();

  const syscall_patch_hook* hook_ptr = find_syscall_hook(t, ip, false, false, instruction_length);
  bool success = false;
  if (hook_ptr) {
    LOG(debug) << "Patching trapping instruction at " << ip << " tid " << t->tid;

    success = patch_syscall_with_hook(*this, t, *hook_ptr, instruction_length, SYS_rrcall_rdtsc);
  }

  if (!success) {
    LOG(debug) << "Failed to patch trapping instruction at " << ip << " tid " << t->tid;
    tried_to_patch_syscall_addresses.insert(ip + instruction_length);
    return false;
  }

  return true;
}

// VDSOs are filled with overhead critical functions related to getting the
// time and current CPU.  We need to ensure that these syscalls get redirected
// into actual trap-into-the-kernel syscalls so rr can intercept them.

template <typename Arch>
static void patch_after_exec_arch(RecordTask* t, Monkeypatcher& patcher);

template <typename Arch>
static void patch_at_preload_init_arch(RecordTask* t, Monkeypatcher& patcher);

template <>
void patch_after_exec_arch<X86Arch>(RecordTask* t, Monkeypatcher& patcher) {
  (void)patcher;
  setup_preload_library_path<X86Arch>(t);
  setup_audit_library_path<X86Arch>(t);

  if (!t->vm()->has_vdso()) {
    patch_auxv_vdso(t, AT_SYSINFO_EHDR, AT_IGNORE);
  } else {
    size_t librrpage_base = RR_PAGE_ADDR - AddressSpace::RRPAGE_RECORD_PAGE_OFFSET*PRELOAD_LIBRARY_PAGE_SIZE;
    patch_auxv_vdso(t, AT_SYSINFO_EHDR, librrpage_base);
    patch_auxv_vdso(t, X86Arch::RR_AT_SYSINFO, librrpage_base +
      AddressSpace::RRVDSO_PAGE_OFFSET*PRELOAD_LIBRARY_PAGE_SIZE);
  }
}

// Monkeypatch x86 vsyscall hook only after the preload library
// has initialized. The vsyscall hook expects to be able to use the syscallbuf.
// Before the preload library has initialized, the regular vsyscall code
// will trigger ptrace traps and be handled correctly by rr.
template <>
void patch_at_preload_init_arch<X86Arch>(RecordTask* t,
                                         Monkeypatcher& patcher) {
  auto params = t->read_mem(
      remote_ptr<rrcall_init_preload_params<X86Arch>>(t->regs().arg1()));
  if (!params.syscallbuf_enabled) {
    return;
  }

  patcher.init_dynamic_syscall_patching(t, params.syscall_patch_hook_count,
                                        params.syscall_patch_hooks);
}

template <>
void patch_after_exec_arch<X64Arch>(RecordTask* t, Monkeypatcher& patcher) {
  setup_preload_library_path<X64Arch>(t);
  setup_audit_library_path<X64Arch>(t);

  for (const auto& m : t->vm()->maps()) {
    auto& km = m.map;
    patcher.patch_after_mmap(t, km.start(), km.size(),
                             km.file_offset_bytes(), -1,
                             Monkeypatcher::MMAP_EXEC);
  }

  if (!t->vm()->has_vdso()) {
    patch_auxv_vdso(t, AT_SYSINFO_EHDR, AT_IGNORE);
  } else {
    size_t librrpage_base = RR_PAGE_ADDR - AddressSpace::RRPAGE_RECORD_PAGE_OFFSET*PRELOAD_LIBRARY_PAGE_SIZE;
    patch_auxv_vdso(t, AT_SYSINFO_EHDR, librrpage_base);
  }
}

template <>
void patch_after_exec_arch<ARM64Arch>(RecordTask* t, Monkeypatcher& patcher) {
  setup_preload_library_path<ARM64Arch>(t);
  setup_audit_library_path<ARM64Arch>(t);

  for (const auto& m : t->vm()->maps()) {
    auto& km = m.map;
    patcher.patch_after_mmap(t, km.start(), km.size(),
                             km.file_offset_bytes(), -1,
                             Monkeypatcher::MMAP_EXEC);
  }

  if (!t->vm()->has_vdso()) {
    patch_auxv_vdso(t, AT_SYSINFO_EHDR, AT_IGNORE);
  } else {
    size_t librrpage_base = RR_PAGE_ADDR - AddressSpace::RRPAGE_RECORD_PAGE_OFFSET*PRELOAD_LIBRARY_PAGE_SIZE;
    patch_auxv_vdso(t, AT_SYSINFO_EHDR, librrpage_base);
  }
}

template <>
void patch_at_preload_init_arch<X64Arch>(RecordTask* t,
                                         Monkeypatcher& patcher) {
  auto params = t->read_mem(
      remote_ptr<rrcall_init_preload_params<X64Arch>>(t->regs().arg1()));
  if (!params.syscallbuf_enabled) {
    return;
  }

  patcher.init_dynamic_syscall_patching(t, params.syscall_patch_hook_count,
                                        params.syscall_patch_hooks);
}

template <>
void patch_at_preload_init_arch<ARM64Arch>(RecordTask* t,
                                           Monkeypatcher& patcher) {
  auto params = t->read_mem(
      remote_ptr<rrcall_init_preload_params<ARM64Arch>>(t->regs().orig_arg1()));
  if (!params.syscallbuf_enabled) {
    return;
  }

  patcher.init_dynamic_syscall_patching(t, params.syscall_patch_hook_count,
                                        params.syscall_patch_hooks);
}

void Monkeypatcher::patch_after_exec(RecordTask* t) {
  ASSERT(t, 1 == t->vm()->task_set().size())
      << "Can't have multiple threads immediately after exec!";

  RR_ARCH_FUNCTION(patch_after_exec_arch, t->arch(), t, *this);
}

void Monkeypatcher::patch_at_preload_init(RecordTask* t) {
  // NB: the tracee can't be interrupted with a signal while
  // we're processing the rrcall, because it's masked off all
  // signals.
  RR_ARCH_FUNCTION(patch_at_preload_init_arch, t->arch(), t, *this);
}

static remote_ptr<void> resolve_address(ElfReader& reader, uintptr_t elf_addr,
                                        remote_ptr<void> map_start,
                                        size_t map_size,
                                        uintptr_t map_offset) {
  uintptr_t file_offset;
  if (!reader.addr_to_offset(elf_addr, file_offset)) {
    LOG(warn) << "ELF address " << HEX(elf_addr) << " not in file";
  }
  if (file_offset < map_offset || file_offset + 32 > map_offset + map_size) {
    // The value(s) to be set are outside the mapped range. This happens
    // because code and data can be mapped in separate, partial mmaps in which
    // case some symbols will be outside the mapped range.
    return nullptr;
  }
  return map_start + uintptr_t(file_offset - map_offset);
}

static void set_and_record_bytes(RecordTask* t, ElfReader& reader,
                                 uintptr_t elf_addr, const void* bytes,
                                 size_t size, remote_ptr<void> map_start,
                                 size_t map_size, size_t map_offset) {
  remote_ptr<void> addr =
    resolve_address(reader, elf_addr, map_start, map_size, map_offset);
  if (!addr) {
    return;
  }
  bool ok = true;
  t->write_bytes_helper(addr, size, bytes, &ok);
  // Writing can fail when the value appears to be in the mapped range, but it
  // actually is beyond the file length.
  if (ok) {
    t->record_local(addr, size, bytes);
  }
}

/**
 * Patch _dl_runtime_resolve_(fxsave,xsave,xsavec) to clear "FDP Data Pointer"
 * register so that CPU-specific behaviors involving that register don't leak
 * into stack memory.
 */
static void patch_dl_runtime_resolve(Monkeypatcher& patcher,
                                     RecordTask* t, ElfReader& reader,
                                     uintptr_t elf_addr,
                                     remote_ptr<void> map_start,
                                     size_t map_size,
                                     size_t map_offset) {
  if (t->arch() != x86_64) {
    return;
  }
  remote_ptr<void> addr =
    resolve_address(reader, elf_addr, map_start, map_size, map_offset);
  if (!addr) {
    return;
  }

  uint8_t impl[X64DLRuntimeResolve::size + X64EndBr::size];
  uint8_t *impl_start = impl;
  t->read_bytes(addr, impl);
  if (X64EndBr::match(impl) || X86EndBr::match(impl)) {
    assert(X64EndBr::size == X86EndBr::size);
    LOG(debug) << "Starts with endbr, skipping";
    addr += X64EndBr::size;
    impl_start += X64EndBr::size;
  }

  if (!X64DLRuntimeResolve::match(impl_start) &&
      !X64DLRuntimeResolve2::match(impl_start)) {
    LOG(warn) << "_dl_runtime_resolve implementation doesn't look right";
    return;
  }

  uint8_t call_patch[X64CallMonkeypatch::size];
  // We're patching in a relative call, so we need to compute the offset from
  // the end of the call to our actual destination.
  auto call_patch_start = addr.cast<uint8_t>();
  auto call_patch_end = call_patch_start + sizeof(call_patch);

  remote_ptr<uint8_t> extended_call_start =
      allocate_extended_jump_x86ish<X64DLRuntimeResolvePrelude>(
          t, patcher.extended_jump_pages, call_patch_end);
  if (extended_call_start.is_null()) {
    return;
  }
  uint8_t stub_patch[X64DLRuntimeResolvePrelude::size];
  X64DLRuntimeResolvePrelude::substitute(stub_patch);
  write_and_record_bytes(t, extended_call_start, stub_patch);

  intptr_t call_offset = extended_call_start - call_patch_end;
  int32_t call_offset32 = (int32_t)call_offset;
  ASSERT(t, call_offset32 == call_offset)
      << "allocate_extended_jump_x86ish didn't work";
  X64CallMonkeypatch::substitute(call_patch, call_offset32);
  write_and_record_bytes(t, call_patch_start, call_patch);

  // pad with NOPs to the next instruction
  static const uint8_t NOP = 0x90;
  uint8_t nops[X64DLRuntimeResolve::size - sizeof(call_patch)];
  memset(nops, NOP, sizeof(nops));
  write_and_record_mem(t, call_patch_start + sizeof(call_patch), nops,
                       sizeof(nops));
}

static bool file_may_need_instrumentation(const AddressSpace::Mapping& map) {
  size_t file_part = map.map.fsname().rfind('/');
  if (file_part == string::npos) {
    file_part = 0;
  } else {
    ++file_part;
  }
  const string& fsname = map.map.fsname();
  return fsname.find("libpthread", file_part) != string::npos ||
    fsname.find("ld", file_part) != string::npos;
}

void Monkeypatcher::patch_after_mmap(RecordTask* t, remote_ptr<void> start,
                                     size_t size, size_t offset_bytes,
                                     int child_fd, MmapMode mode) {
  const auto& map = t->vm()->mapping_of(start);
  if (file_may_need_instrumentation(map) &&
      (t->arch() == x86 || t->arch() == x86_64)) {
    ScopedFd open_fd;
    if (child_fd >= 0) {
      open_fd = t->open_fd(child_fd, O_RDONLY);
      ASSERT(t, open_fd.is_open()) << "Failed to open child fd " << child_fd;
    } else {
      char buf[100];
      sprintf(buf, "/proc/%d/map_files/%llx-%llx", t->tid,
              (long long)start.as_int(), (long long)start.as_int() + size);
      // Reading these directly requires CAP_SYS_ADMIN, so open the link target
      // instead.
      char link[PATH_MAX];
      int ret = readlink(buf, link, sizeof(link) - 1);
      if (ret < 0) {
        return;
      }
      link[ret] = 0;
      open_fd = ScopedFd(link, O_RDONLY);
      if (!open_fd.is_open()) {
        return;
      }
    }
    ElfFileReader reader(open_fd, t->arch());
    // Check for symbols first in the library itself, regardless of whether
    // there is a debuglink.  For example, on Fedora 26, the .symtab and
    // .strtab sections are stripped from the debuginfo file for
    // libpthread.so.
    SymbolTable syms = reader.read_symbols(".symtab", ".strtab");
    if (syms.size() == 0) {
      ScopedFd debug_fd = reader.open_debug_file(map.map.fsname());
      if (debug_fd.is_open()) {
        ElfFileReader debug_reader(debug_fd, t->arch());
        syms = debug_reader.read_symbols(".symtab", ".strtab");
      }
    }
    for (size_t i = 0; i < syms.size(); ++i) {
      if (syms.is_name(i, "__elision_aconf")) {
        static const int zero = 0;
        // Setting __elision_aconf.retry_try_xbegin to zero means that
        // pthread rwlocks don't try to use elision at all. See ELIDE_LOCK
        // in glibc's elide.h.
        set_and_record_bytes(t, reader, syms.addr(i) + 8, &zero, sizeof(zero),
                             start, size, offset_bytes);
      }
      if (syms.is_name(i, "elision_init")) {
        // Make elision_init return without doing anything. This means
        // the __elision_available and __pthread_force_elision flags will
        // remain zero, disabling elision for mutexes. See glibc's
        // elision-conf.c.
        static const uint8_t ret = 0xC3;
        set_and_record_bytes(t, reader, syms.addr(i), &ret, sizeof(ret), start,
                             size, offset_bytes);
      }
      // The following operations can only be applied once because after the
      // patch is applied the code no longer matches the expected template.
      // For replaying a replay to work, we need to only apply these changes
      // during a real exec, not during the mmap operations performed when rr
      // replays an exec.
      if (mode == MMAP_EXEC &&
          (syms.is_name(i, "_dl_runtime_resolve_fxsave") ||
           syms.is_name(i, "_dl_runtime_resolve_xsave") ||
           syms.is_name(i, "_dl_runtime_resolve_xsavec"))) {
        patch_dl_runtime_resolve(*this, t, reader, syms.addr(i), start, size,
                                 offset_bytes);
      }
    }
  }
}

} // namespace rr
