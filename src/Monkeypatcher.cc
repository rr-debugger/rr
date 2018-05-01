/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "Monkeypatcher.h"

#include <limits.h>

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
                                   size_t size, const void* buf) {
  t->write_bytes_helper(child_addr, size, buf);
  t->record_local(child_addr, size, buf);
}

template <size_t N>
static void write_and_record_bytes(RecordTask* t, remote_ptr<void> child_addr,
                                   const uint8_t (&buf)[N]) {
  write_and_record_bytes(t, child_addr, N, buf);
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
 * SYSCALLBUF_LIB_FILENAME_PADDED which is big enough to hold either the
 * 32-bit or 64-bit preload library file names. Immediately after exec we
 * enter this function, which patches the environment variable value with
 * the correct library name for the task's architecture.
 *
 * It's possible for this to fail if a tracee alters the LD_PRELOAD value
 * and then does an exec. That's just too bad. If we ever have to handle that,
 * we should modify the environment passed to the exec call. This function
 * failing isn't necessarily fatal; a tracee might not rely on the functions
 * overridden by the preload library, or might override them itself (e.g.
 * because we're recording an rr replay).
 */
template <typename Arch> static void setup_preload_library_path(RecordTask* t) {
  static_assert(sizeof(SYSCALLBUF_LIB_FILENAME_PADDED) ==
                    sizeof(SYSCALLBUF_LIB_FILENAME_32),
                "filename length mismatch");

  const char* lib_name =
      sizeof(typename Arch::unsigned_word) < sizeof(uintptr_t)
          ? SYSCALLBUF_LIB_FILENAME_32
          : SYSCALLBUF_LIB_FILENAME_PADDED;

  auto p = t->regs().sp().cast<typename Arch::unsigned_word>();
  auto argc = t->read_mem(p);
  p += 1 + argc + 1; // skip argc, argc parameters, and trailing NULL
  while (true) {
    auto envp = t->read_mem(p);
    if (!envp) {
      LOG(debug) << "LD_PRELOAD not found";
      return;
    }
    string env = t->read_c_str(envp);
    if (env.find("LD_PRELOAD=") != 0) {
      ++p;
      continue;
    }
    size_t lib_pos = env.find(SYSCALLBUF_LIB_FILENAME_BASE);
    if (lib_pos == string::npos) {
      LOG(debug) << SYSCALLBUF_LIB_FILENAME_BASE " not found in LD_PRELOAD";
      return;
    }
    size_t next_colon = env.find(':', lib_pos);
    if (next_colon != string::npos) {
      while ((next_colon + 1 < env.length()) &&
             (env[next_colon + 1] == ':' || env[next_colon + 1] == 0)) {
        ++next_colon;
      }
      if (next_colon + 1 <
          lib_pos + sizeof(SYSCALLBUF_LIB_FILENAME_PADDED) - 1) {
        LOG(debug) << "Insufficient space for " << lib_name
                   << " in LD_PRELOAD before next ':'";
        return;
      }
    }
    if (env.length() < lib_pos + sizeof(SYSCALLBUF_LIB_FILENAME_PADDED) - 1) {
      LOG(debug) << "Insufficient space for " << lib_name
                 << " in LD_PRELOAD before end of string";
      return;
    }
    remote_ptr<void> dest = envp + lib_pos;
    write_and_record_mem(t, dest.cast<char>(), lib_name,
                         sizeof(SYSCALLBUF_LIB_FILENAME_PADDED) - 1);
    return;
  }
}

void Monkeypatcher::init_dynamic_syscall_patching(
    RecordTask* t, int syscall_patch_hook_count,
    remote_ptr<struct syscall_patch_hook> syscall_patch_hooks) {
  if (syscall_patch_hook_count) {
    syscall_hooks = t->read_mem(syscall_patch_hooks, syscall_patch_hook_count);
  }
}

template <typename Arch>
static bool patch_syscall_with_hook_arch(Monkeypatcher& patcher, RecordTask* t,
                                         const syscall_patch_hook& hook);

template <typename StubPatch>
static void substitute(uint8_t* buffer, uint64_t return_addr,
                       uint32_t trampoline_relative_addr);

template <typename ExtendedJumpPatch>
static void substitute_extended_jump(uint8_t* buffer, uint64_t patch_addr,
                                     uint64_t return_addr,
                                     uint64_t target_addr);

template <>
void substitute_extended_jump<X86SyscallStubExtendedJump>(
    uint8_t* buffer, uint64_t patch_addr, uint64_t return_addr,
    uint64_t target_addr) {
  int64_t offset =
      target_addr -
      (patch_addr + X86SyscallStubExtendedJump::trampoline_relative_addr_end);
  // An offset that appears to be > 2GB is OK here, since EIP will just
  // wrap around.
  X86SyscallStubExtendedJump::substitute(buffer, (uint32_t)return_addr,
                                         (uint32_t)offset);
}

template <>
void substitute_extended_jump<X64SyscallStubExtendedJump>(
    uint8_t* buffer, uint64_t, uint64_t return_addr, uint64_t target_addr) {
  X64SyscallStubExtendedJump::substitute(buffer, (uint32_t)return_addr,
                                         (uint32_t)(return_addr >> 32),
                                         target_addr);
}

/**
 * Allocate an extended jump in an extended jump page and return its address.
 * The resulting address must be within 2G of from_end, and the instruction
 * there must jump to to_start.
 */
template <typename ExtendedJumpPatch>
static remote_ptr<uint8_t> allocate_extended_jump(
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
      remote.infallible_mmap_syscall(addr, page_size(), prot, flags, -1, 0);
      KernelMapping recorded(addr, addr + page_size(), string(),
                             KernelMapping::NO_DEVICE, KernelMapping::NO_INODE,
                             prot, flags);
      t->vm()->map(t, addr, page_size(), prot, flags, 0, string(),
                   KernelMapping::NO_DEVICE, KernelMapping::NO_INODE, nullptr,
                   &recorded);
      t->vm()->mapping_flags_of(addr) |= AddressSpace::Mapping::IS_PATCH_STUBS;
      t->trace_writer().write_mapped_region(t, recorded, recorded.fake_stat(),
                                            TraceWriter::PATCH_MAPPING);
    }

    pages.push_back(Monkeypatcher::ExtendedJumpPage(addr));
    page = &pages.back();
  }

  remote_ptr<uint8_t> jump_addr = page->addr + page->allocated;
  page->allocated += ExtendedJumpPatch::size;
  return jump_addr;
}

bool Monkeypatcher::is_jump_stub_instruction(remote_code_ptr ip) {
  remote_ptr<uint8_t> pp = ip.to_data_ptr<uint8_t>();
  auto it = syscallbuf_stubs.upper_bound(pp);
  if (it == syscallbuf_stubs.begin()) {
    return false;
  }
  --it;
  return it->first <= pp && pp < it->first + it->second;
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
 */
template <typename JumpPatch, typename ExtendedJumpPatch>
static bool patch_syscall_with_hook_x86ish(Monkeypatcher& patcher,
                                           RecordTask* t,
                                           const syscall_patch_hook& hook) {
  uint8_t jump_patch[JumpPatch::size];
  // We're patching in a relative jump, so we need to compute the offset from
  // the end of the jump to our actual destination.
  auto jump_patch_start = t->regs().ip().to_data_ptr<uint8_t>();
  auto jump_patch_end = jump_patch_start + sizeof(jump_patch);

  remote_ptr<uint8_t> extended_jump_start =
      allocate_extended_jump<ExtendedJumpPatch>(
          t, patcher.extended_jump_pages, jump_patch_end);
  if (extended_jump_start.is_null()) {
    return false;
  }

  uint8_t stub_patch[ExtendedJumpPatch::size];
  auto return_addr =
    jump_patch_start.as_int() + syscall_instruction_length(x86_64) +
    hook.next_instruction_length;
  substitute_extended_jump<ExtendedJumpPatch>(stub_patch,
                                              extended_jump_start.as_int(),
                                              return_addr,
                                              hook.hook_address);
  write_and_record_bytes(t, extended_jump_start, stub_patch);

  patcher.syscallbuf_stubs[extended_jump_start] = ExtendedJumpPatch::size;

  intptr_t jump_offset = extended_jump_start - jump_patch_end;
  int32_t jump_offset32 = (int32_t)jump_offset;
  ASSERT(t, jump_offset32 == jump_offset)
      << "allocate_extended_jump didn't work";

  JumpPatch::substitute(jump_patch, jump_offset32);
  write_and_record_bytes(t, jump_patch_start, jump_patch);

  // pad with NOPs to the next instruction
  static const uint8_t NOP = 0x90;
  DEBUG_ASSERT(syscall_instruction_length(x86_64) ==
               syscall_instruction_length(x86));
  uint8_t nops[syscall_instruction_length(x86_64) +
               hook.next_instruction_length - sizeof(jump_patch)];
  memset(nops, NOP, sizeof(nops));
  write_and_record_mem(t, jump_patch_start + sizeof(jump_patch), nops,
                       sizeof(nops));

  return true;
}

template <>
bool patch_syscall_with_hook_arch<X86Arch>(Monkeypatcher& patcher,
                                           RecordTask* t,
                                           const syscall_patch_hook& hook) {
  return patch_syscall_with_hook_x86ish<X86SysenterVsyscallSyscallHook,
                                        X86SyscallStubExtendedJump>(patcher, t,
                                                                    hook);
}

template <>
bool patch_syscall_with_hook_arch<X64Arch>(Monkeypatcher& patcher,
                                           RecordTask* t,
                                           const syscall_patch_hook& hook) {
  return patch_syscall_with_hook_x86ish<X64JumpMonkeypatch,
                                        X64SyscallStubExtendedJump>(patcher, t,
                                                                    hook);
}

static bool patch_syscall_with_hook(Monkeypatcher& patcher, RecordTask* t,
                                    const syscall_patch_hook& hook) {
  RR_ARCH_FUNCTION(patch_syscall_with_hook_arch, t->arch(), patcher, t, hook);
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

bool Monkeypatcher::try_patch_syscall(RecordTask* t) {
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
  if (tried_to_patch_syscall_addresses.count(ip)) {
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

  uint8_t following_bytes[256];
  size_t bytes_count = t->read_bytes_fallible(
      ip.to_data_ptr<uint8_t>(), sizeof(following_bytes), following_bytes);

  intptr_t syscallno = r.original_syscallno();
  for (auto& hook : syscall_hooks) {
    if (bytes_count >= hook.next_instruction_length &&
        memcmp(following_bytes, hook.next_instruction_bytes,
               hook.next_instruction_length) == 0) {
      // Search for a following short-jump instruction that targets an
      // instruction
      // after the syscall. False positives are OK.
      // glibc-2.23.1-8.fc24.x86_64's __clock_nanosleep needs this.
      bool found_potential_interfering_branch = false;
      // If this was a VDSO syscall we patched, we don't have to worry about
      // this check since the function doesn't do anything except execute our
      // syscall and return.
      // Otherwise the Linux 4.12 VDSO triggers the interfering-branch check.
      if (!patched_vdso_syscalls.count(
              ip.decrement_by_syscall_insn_length(arch))) {
        for (size_t i = 0; i + 2 <= bytes_count; ++i) {
          uint8_t b = following_bytes[i];
          // Check for short conditional or unconditional jump
          if (b == 0xeb || (b >= 0x70 && b < 0x80)) {
            int offset = i + 2 + (int8_t)following_bytes[i + 1];
            if (hook.is_multi_instruction
                    ? (offset >= 0 && offset < hook.next_instruction_length)
                    : offset == 0) {
              LOG(debug) << "Found potential interfering branch at "
                         << ip.to_data_ptr<uint8_t>() + i;
              // We can't patch this because it would jump straight back into
              // the middle of our patch code.
              found_potential_interfering_branch = true;
            }
          }
        }
      }

      if (!found_potential_interfering_branch) {
        if (!safe_for_syscall_patching(ip, ip + hook.next_instruction_length,
                                       t)) {
          LOG(debug)
              << "Temporarily declining to patch syscall at " << ip
              << " because a different task has its ip in the patched range";
          return false;
        }

        LOG(debug) << "Patched syscall at " << ip << " syscall "
                   << syscall_name(syscallno, t->arch()) << " tid " << t->tid
                   << " bytes "
                   << bytes_to_string(
                          following_bytes,
                          min(bytes_count,
                              sizeof(
                                  syscall_patch_hook::next_instruction_bytes)));

        // Get out of executing the current syscall before we patch it.
        if (!t->exit_syscall_and_prepare_restart()) {
          return false;
        }

        patch_syscall_with_hook(*this, t, hook);

        // Return to caller, which resume normal execution.
        return true;
      }
    }
  }
  LOG(debug) << "Failed to patch syscall at " << ip << " syscall "
             << syscall_name(syscallno, t->arch()) << " tid " << t->tid
             << " bytes "
             << bytes_to_string(
                    following_bytes,
                    min(bytes_count,
                        sizeof(syscall_patch_hook::next_instruction_bytes)));
  tried_to_patch_syscall_addresses.insert(ip);
  return false;
}

class VdsoReader : public ElfReader {
public:
  VdsoReader(RecordTask* t) : ElfReader(t->arch()), t(t) {}
  virtual bool read(size_t offset, size_t size, void* buf) override {
    bool ok = true;
    t->read_bytes_helper(t->vm()->vdso().start() + offset, size, buf, &ok);
    return ok;
  }
  RecordTask* t;
};

/**
 * Return true iff |addr| points to a known |__kernel_vsyscall()|
 * implementation.
 */
static bool is_kernel_vsyscall(RecordTask* t, remote_ptr<void> addr) {
  uint8_t impl[X86SysenterVsyscallImplementationAMD::size];
  t->read_bytes(addr, impl);
  return X86SysenterVsyscallImplementation::match(impl) ||
         X86SysenterVsyscallImplementationAMD::match(impl);
}

static const uintptr_t MAX_VDSO_SIZE = 16384;
static const uintptr_t VDSO_ABSOLUTE_ADDRESS = 0xffffe000;

/**
 * Return the address of a recognized |__kernel_vsyscall()|
 * implementation in |t|'s address space.
 */
static remote_ptr<void> locate_and_verify_kernel_vsyscall(
    RecordTask* t, ElfReader& reader, const SymbolTable& syms) {
  remote_ptr<void> kernel_vsyscall = nullptr;
  // It is unlikely but possible that multiple, versioned __kernel_vsyscall
  // symbols will exist.  But we can't rely on setting |kernel_vsyscall| to
  // catch that case, because only one of the versioned symbols will
  // actually match what we expect to see, and the matching one might be
  // the last one.  Therefore, we have this separate flag to alert us to
  // this possibility.
  bool seen_kernel_vsyscall = false;

  for (size_t i = 0; i < syms.size(); ++i) {
    if (syms.is_name(i, "__kernel_vsyscall")) {
      uintptr_t file_offset;
      if (!reader.addr_to_offset(syms.addr(i), file_offset)) {
        continue;
      }
      // The symbol values can be absolute or relative addresses.
      if (file_offset >= VDSO_ABSOLUTE_ADDRESS) {
        file_offset -= VDSO_ABSOLUTE_ADDRESS;
      }
      if (file_offset > MAX_VDSO_SIZE) {
        // With 4.2.8-300.fc23.x86_64, execve_loop_32 seems to once in a while
        // see a VDSO with a crazy file offset in it which is a duplicate
        // __kernel_vsyscall. Bizzarro. Ignore it.
        continue;
      }
      ASSERT(t, !seen_kernel_vsyscall);
      seen_kernel_vsyscall = true;
      // The ELF information in the VDSO assumes that the VDSO
      // is always loaded at a particular address.  The kernel,
      // however, subjects the VDSO to ASLR, which means that
      // we have to adjust the offsets properly.
      auto vdso_start = t->vm()->vdso().start();
      remote_ptr<void> candidate = vdso_start + file_offset;

      if (is_kernel_vsyscall(t, candidate)) {
        kernel_vsyscall = candidate;
      }
    }
  }

  return kernel_vsyscall;
}

// VDSOs are filled with overhead critical functions related to getting the
// time and current CPU.  We need to ensure that these syscalls get redirected
// into actual trap-into-the-kernel syscalls so rr can intercept them.

template <typename Arch>
static void patch_after_exec_arch(RecordTask* t, Monkeypatcher& patcher);

template <typename Arch>
static void patch_at_preload_init_arch(RecordTask* t, Monkeypatcher& patcher);

struct named_syscall {
  const char* name;
  int syscall_number;
};

static void erase_section(VdsoReader& reader, const char* name) {
  SectionOffsets offsets = reader.find_section_file_offsets(name);
  if (offsets.end > offsets.start) {
    vector<uint8_t> zeroes;
    zeroes.resize(offsets.end - offsets.start);
    memset(zeroes.data(), 0, zeroes.size());
    write_and_record_bytes(reader.t,
        reader.t->vm()->vdso().start() + offsets.start,
        offsets.end - offsets.start, zeroes.data());
  }
}

static void obliterate_debug_info(VdsoReader& reader) {
  erase_section(reader, ".eh_frame");
  erase_section(reader, ".eh_frame_hdr");
  erase_section(reader, ".note");
}

// Monkeypatch x86-32 vdso syscalls immediately after exec. The vdso syscalls
// will cause replay to fail if called by the dynamic loader or some library's
// static constructors, so we can't wait for our preload library to be
// initialized. Fortunately we're just replacing the vdso code with real
// syscalls so there is no dependency on the preload library at all.
template <>
void patch_after_exec_arch<X86Arch>(RecordTask* t, Monkeypatcher& patcher) {
  setup_preload_library_path<X86Arch>(t);

  VdsoReader reader(t);
  auto syms = reader.read_symbols(".dynsym", ".dynstr");
  patcher.x86_vsyscall = locate_and_verify_kernel_vsyscall(t, reader, syms);
  if (!patcher.x86_vsyscall) {
    FATAL() << "Failed to monkeypatch vdso: your __kernel_vsyscall() wasn't "
               "recognized.\n"
               "    Syscall buffering is now effectively disabled.  If you're "
               "OK with\n"
               "    running rr without syscallbuf, then run the recorder "
               "passing the\n"
               "    --no-syscall-buffer arg.\n"
               "    If you're *not* OK with that, file an issue.";
  }

  // Patch __kernel_vsyscall to use int 80 instead of sysenter.
  // During replay we may remap the VDSO to a new address, and the sysenter
  // instruction would return to the old address, so we must make sure sysenter
  // is never used.
  uint8_t patch[X86SysenterVsyscallUseInt80::size];
  X86SysenterVsyscallUseInt80::substitute(patch);
  write_and_record_bytes(t, patcher.x86_vsyscall, patch);
  LOG(debug) << "monkeypatched __kernel_vsyscall to use int $80";

  auto vdso_start = t->vm()->vdso().start();

  static const named_syscall syscalls_to_monkeypatch[] = {
#define S(n) { "__vdso_" #n, X86Arch::n }
    S(clock_gettime), S(gettimeofday), S(time),
#undef S
  };

  for (size_t i = 0; i < syms.size(); ++i) {
    for (size_t j = 0; j < array_length(syscalls_to_monkeypatch); ++j) {
      if (syms.is_name(i, syscalls_to_monkeypatch[j].name)) {
        uintptr_t file_offset;
        if (!reader.addr_to_offset(syms.addr(i), file_offset)) {
          continue;
        }
        if (file_offset > MAX_VDSO_SIZE) {
          // With 4.3.3-301.fc23.x86_64, once in a while we
          // see a VDSO symbol with a crazy file offset in it which is a
          // duplicate of another symbol. Bizzarro. Ignore it.
          continue;
        }

        uintptr_t absolute_address = vdso_start.as_int() + file_offset;

        uint8_t patch[X86VsyscallMonkeypatch::size];
        uint32_t syscall_number = syscalls_to_monkeypatch[j].syscall_number;
        X86VsyscallMonkeypatch::substitute(patch, syscall_number);

        write_and_record_bytes(t, absolute_address, patch);
        // Record the location of the syscall instruction, skipping the
        // "push %ebx; mov $syscall_number,%eax".
        patcher.patched_vdso_syscalls.insert(
            remote_code_ptr(absolute_address + 6));
        LOG(debug) << "monkeypatched " << syscalls_to_monkeypatch[j].name
                   << " to syscall "
                   << syscalls_to_monkeypatch[j].syscall_number;
      }
    }
  }
  obliterate_debug_info(reader);
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

  auto kernel_vsyscall = patcher.x86_vsyscall;

  // Luckily, linux is happy for us to scribble directly over
  // the vdso mapping's bytes without mprotecting the region, so
  // we don't need to prepare remote syscalls here.
  remote_ptr<void> syscallhook_vsyscall_entry =
      params.syscallhook_vsyscall_entry;

  uint8_t patch[X86SysenterVsyscallSyscallHook::size];

  if (safe_for_syscall_patching(kernel_vsyscall.as_int(),
                                kernel_vsyscall.as_int() + sizeof(patch), t)) {
    // We're patching in a relative jump, so we need to compute the offset from
    // the end of the jump to our actual destination.
    X86SysenterVsyscallSyscallHook::substitute(
        patch,
        syscallhook_vsyscall_entry.as_int() -
            (kernel_vsyscall + sizeof(patch)).as_int());
    write_and_record_bytes(t, kernel_vsyscall, patch);
    LOG(debug) << "monkeypatched __kernel_vsyscall to jump to "
               << HEX(syscallhook_vsyscall_entry.as_int());
  } else {
    if (!Flags::get().suppress_environment_warnings) {
      fprintf(stderr, "Unable to patch __kernel_vsyscall because a LD_PRELOAD "
                      "thread is blocked in it; recording will be slow\n");
    }
    LOG(debug) << "Unable to patch __kernel_vsyscall because a LD_PRELOAD "
                  "thread is blocked in it";
  }

  patcher.init_dynamic_syscall_patching(t, params.syscall_patch_hook_count,
                                        params.syscall_patch_hooks);
}

// Monkeypatch x86-64 vdso syscalls immediately after exec. The vdso syscalls
// will cause replay to fail if called by the dynamic loader or some library's
// static constructors, so we can't wait for our preload library to be
// initialized. Fortunately we're just replacing the vdso code with real
// syscalls so there is no dependency on the preload library at all.
template <>
void patch_after_exec_arch<X64Arch>(RecordTask* t, Monkeypatcher& patcher) {
  setup_preload_library_path<X64Arch>(t);

  auto vdso_start = t->vm()->vdso().start();
  size_t vdso_size = t->vm()->vdso().size();

  VdsoReader reader(t);
  auto syms = reader.read_symbols(".dynsym", ".dynstr");

  static const named_syscall syscalls_to_monkeypatch[] = {
#define S(n) { "__vdso_" #n, X64Arch::n }
    S(clock_gettime), S(gettimeofday), S(time),
    // getcpu isn't supported by rr, so any changes to this monkeypatching
    // scheme for efficiency's sake will have to ensure that getcpu gets
    // converted to an actual syscall so rr will complain appropriately.
    S(getcpu),
#undef S
  };

  for (auto& syscall : syscalls_to_monkeypatch) {
    for (size_t i = 0; i < syms.size(); ++i) {
      if (syms.is_name(i, syscall.name)) {
        uintptr_t file_offset;
        if (!reader.addr_to_offset(syms.addr(i), file_offset)) {
          LOG(debug) << "Can't convert address " << HEX(syms.addr(i))
                     << " to offset";
          continue;
        }
        uint64_t file_offset_64 = file_offset;
        // Absolutely-addressed symbols in the VDSO claim to start here.
        static const uint64_t vdso_static_base = 0xffffffffff700000LL;
        static const uint64_t vdso_max_size = 0xffffLL;
        uint64_t sym_offset = file_offset_64 & vdso_max_size;

        // In 4.4.6-301.fc23.x86_64 we occasionally see a grossly invalid
        // address, se.g. 0x11c6970 for __vdso_getcpu. :-(
        if ((file_offset_64 >= vdso_static_base &&
             file_offset_64 < vdso_static_base + vdso_size) ||
            file_offset_64 < vdso_size) {
          uintptr_t absolute_address = vdso_start.as_int() + sym_offset;

          uint8_t patch[X64VsyscallMonkeypatch::size];
          uint32_t syscall_number = syscall.syscall_number;
          X64VsyscallMonkeypatch::substitute(patch, syscall_number);

          write_and_record_bytes(t, absolute_address, patch);
          // Record the location of the syscall instruction, skipping the
          // "mov $syscall_number,%eax".
          patcher.patched_vdso_syscalls.insert(
              remote_code_ptr(absolute_address + 5));
          LOG(debug) << "monkeypatched " << syscall.name << " to syscall "
                     << syscall.syscall_number << " at "
                     << HEX(absolute_address) << " (" << HEX(file_offset)
                     << ")";

          // With 4.4.6-301.fc23.x86_64, once in a while we see a VDSO symbol
          // with an incorrect file offset (a small integer) in it
          // which is a duplicate of a previous symbol. Bizzarro. So, stop once
          // we see a valid value for the symbol.
          break;
        } else {
          LOG(debug) << "Ignoring odd file offset " << HEX(file_offset)
                     << "; vdso_static_base=" << HEX(vdso_static_base)
                     << ", size=" << vdso_size;
        }
      }
    }
  }

  obliterate_debug_info(reader);

  for (const auto& m : t->vm()->maps()) {
    auto& km = m.map;
    patcher.patch_after_mmap(t, km.start(), km.size(),
                             km.file_offset_bytes()/page_size(), -1,
                             Monkeypatcher::MMAP_EXEC);
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
                                        size_t map_offset_pages) {
  uintptr_t file_offset;
  if (!reader.addr_to_offset(elf_addr, file_offset)) {
    LOG(warn) << "ELF address " << HEX(elf_addr) << " not in file";
  }
  uintptr_t map_offset = uintptr_t(map_offset_pages) * page_size();
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
                                 size_t map_size, size_t map_offset_pages) {
  remote_ptr<void> addr =
    resolve_address(reader, elf_addr, map_start, map_size, map_offset_pages);
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
                                     size_t map_offset_pages) {
  if (t->arch() != x86_64) {
    return;
  }
  remote_ptr<void> addr =
    resolve_address(reader, elf_addr, map_start, map_size, map_offset_pages);
  if (!addr) {
    return;
  }

  uint8_t impl[X64DLRuntimeResolve::size];
  t->read_bytes(addr, impl);
  if (!X64DLRuntimeResolve::match(impl) &&
      !X64DLRuntimeResolve2::match(impl)) {
    LOG(warn) << "_dl_runtime_resolve implementation doesn't look right";
    return;
  }

  uint8_t jump_patch[X64JumpMonkeypatch::size];
  // We're patching in a relative jump, so we need to compute the offset from
  // the end of the jump to our actual destination.
  auto jump_patch_start = addr.cast<uint8_t>();
  auto jump_patch_end = jump_patch_start + sizeof(jump_patch);

  remote_ptr<uint8_t> extended_jump_start =
      allocate_extended_jump<X64DLRuntimeResolvePrelude>(
          t, patcher.extended_jump_pages, jump_patch_end);
  if (extended_jump_start.is_null()) {
    return;
  }
  uint8_t stub_patch[X64DLRuntimeResolvePrelude::size];
  int64_t return_offset = jump_patch_start.as_int() +
    X64DLRuntimeResolve::size -
    (extended_jump_start.as_int() + X64DLRuntimeResolvePrelude::size);
  if (return_offset != (int32_t)return_offset) {
    LOG(warn) << "Return out of range";
    return;
  }
  X64DLRuntimeResolvePrelude::substitute(stub_patch, (int32_t)return_offset);
  write_and_record_bytes(t, extended_jump_start, stub_patch);

  intptr_t jump_offset = extended_jump_start - jump_patch_end;
  int32_t jump_offset32 = (int32_t)jump_offset;
  ASSERT(t, jump_offset32 == jump_offset)
      << "allocate_extended_jump didn't work";
  X64JumpMonkeypatch::substitute(jump_patch, jump_offset32);
  write_and_record_bytes(t, jump_patch_start, jump_patch);

  // pad with NOPs to the next instruction
  static const uint8_t NOP = 0x90;
  uint8_t nops[X64DLRuntimeResolve::size - sizeof(jump_patch)];
  memset(nops, NOP, sizeof(nops));
  write_and_record_mem(t, jump_patch_start + sizeof(jump_patch), nops,
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
                                     size_t size, size_t offset_pages,
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
                             start, size, offset_pages);
      }
      if (syms.is_name(i, "elision_init")) {
        // Make elision_init return without doing anything. This means
        // the __elision_available and __pthread_force_elision flags will
        // remain zero, disabling elision for mutexes. See glibc's
        // elision-conf.c.
        static const uint8_t ret = 0xC3;
        set_and_record_bytes(t, reader, syms.addr(i), &ret, sizeof(ret), start,
                             size, offset_pages);
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
                                 offset_pages);
      }
    }
  }
}

} // namespace rr
