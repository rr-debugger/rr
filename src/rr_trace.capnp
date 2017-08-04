@0xcaa0b1486c12c629;

using Cxx = import "/capnp/c++.capnp";
$Cxx.namespace("rr::trace");

# We generally use Data instead of Text because for e.g. files there is no
# guarantee the data are valid UTF-8.
# We use the natural system types whenever possible. For example, even though
# negative fds are not possible, we use Int32 for fds to match kernel/library
# APIs. This avoids potential problems where the trace value doesn't fit into
# the range of the type where it is actually used.
# "Must" constraints noted below should be checked by consumers.

# Must not contain any null bytes
using Path = Data;

using Device = UInt64;
using Inode = UInt64;
using RemotePtr = UInt64;

# Must be > 0
using FrameTime = Int64;
# Must be > 0
using Tid = Int32;
# Must be >= 0
using Ticks = Int64;
# Must be >= 0
using Fd = Int32;

struct Header {
  # Always 16 bytes
  uuid @0 :Data;
  bindToCpu @1 :Int32;
  hasCpuidFaulting @2 :Bool;
  # A series of 24-byte records. See CPUIDRecord in util.h
  cpuidRecords @3 :Data;
  syscallbufProtocolVersion @4 :UInt16;
}

struct MMap {
  frameTime @0 :FrameTime;
  # kernel memory mapping data
  start @1 :RemotePtr;
  end @2 :RemotePtr;
  fsname @3 :Data;
  device @4 :Device;
  inode @5 :Inode;
  prot @6 :Int32;
  flags @7 :Int32;
  fileOffsetBytes @8 :Int64;
  # data about the original mapped file
  # (or all-zero if the data has been erased by `rr pack` because we don't
  # expect the original file to be available)
  statMode @9 :UInt32;
  statUid @10 :UInt32;
  statGid @11 :UInt32;
  # must be >= 0
  statSize @12 :Int64;
  statMTime @13 :Int64;
  # how to get the data during replay
  source :union {
    zero @14 :Void;
    trace @15 :Void;
    file :group {
      backingFileName @16 :Data;
    }
  }
}

struct TaskEvent {
  frameTime @0 :FrameTime;
  tid @1 :Tid;
  union {
    clone :group {
      parentTid @2 :Tid;
      flags @3 :Int32;    # Kernel's CLONE_ flags
      ownNsTid @4 :Tid;
    }
    exec :group {
      fileName @5 :Data;
      cmdLine @6 :List(Data);
    }
    exit :group {
      exitStatus @7 :Int32;
    }
  }
}

struct MemWrite {
  tid @0 :Tid;
  addr @1 :RemotePtr;
  size @2 :UInt64;
}

enum Arch {
  x86 @0;
  x8664 @1;
}

struct Registers {
  # May be empty. Format determined by Frame::arch
  raw @0 :Data;
}

struct ExtraRegisters {
  # May be empty. Format determined by Frame::arch
  raw @0 :Data;
}

enum SyscallState {
  enteringPtrace @0;
  entering @1;
  exiting @2;
}

enum SignalDisposition {
  fatal @0;
  userHandler @1;
  ignored @2;
}

struct Signal {
  # May differ from the Frame's arch, e.g. on x86-64 we always save
  # siginfo in x86-64 format even for x86-32 Frames.
  siginfoArch @0 :Arch;
  # Native 'siginfo_t' for the given siginfoArch.
  siginfo @1 :Data;
  deterministic @2 :Bool;
  disposition @3 :SignalDisposition;
}

# Some file opens are "special" (e.g. opening /dev/tty, or /proc/.../mem)
# and get recorded in the trace as such
struct OpenedFd {
  fd @0 :Fd;
  # Absolute pathname, or "terminal" if we opened the terminal in some way
  path @1 :Data;
}

struct Frame {
  tid @0 :Tid;
  ticks @1 :Ticks;
  monotonicSec @2 :Float64;
  memWrites @3 :List(MemWrite);
  # Determines the format of 'registers' and 'extraRegisters'
  arch @4 :Arch;
  registers @5 :Registers;
  extraRegisters @6 :ExtraRegisters;
  event :union {
    instructionTrap @7 :Void;
    patchSyscall @8 :Void;
    syscallbufAbortCommit @9 :Void;
    syscallbufReset @10 :Void;
    sched @11 :Void;
    growMap @12 :Void;
    signal @13 :Signal;
    signalDelivery @14 :Signal;
    signalHandler @15 :Signal;
    exit @16 :Void;
    syscallbufFlush :group {
      # Not used during replay, but affects virtual memory layout so
      # useful for some tools
      # An array of 'mprotect_record's (see preload_interface.h)
      mprotectRecords @17 :Data;
    }
    syscall :group {
      # Linux supports system calls that are of a different architecture to
      # the task's actual architecture (in particular, x86-32 syscalls via
      # int $0x80 in an x86-64 process)
      arch @18 :Arch;
      number @19 :Int32;
      state @20 :SyscallState;
      failedDuringPreparation @21 :Bool;
      extra :union {
        none @22 :Void;
        # Must be >= 0
        writeOffset @23 :Int64;
        execFdsToClose @24 :List(Fd);
        openedFds @25 :List(OpenedFd);
      }
    }
  }
}
