# rr ReplaySession schema

@0xf55676ebd869d6c1;

using Cxx = import "/capnp/c++.capnp";
$Cxx.namespace("rr::pcp");

using import "rr_trace.capnp".Registers;
using import "rr_trace.capnp".ExtraRegisters;
using import "rr_trace.capnp".Arch;
using import "rr_trace.capnp".RemoteFd;
using import "rr_trace.capnp".CString;
using import "rr_trace.capnp".Device;
using import "rr_trace.capnp".Inode;
using import "rr_trace.capnp".RemotePtr;
using import "rr_trace.capnp".FrameTime;
using import "rr_trace.capnp".Tid;
using import "rr_trace.capnp".Fd;
using import "rr_trace.capnp".Path;
using import "rr_trace.capnp".Ticks;

struct ExtendedTaskId {
  groupId @0 :Tid;
  groupSerial @1: UInt32;
  taskId @2 :Tid;
  taskSerial @3: UInt32;
}

using FileMonitorType = Int32;
struct FileMonitor {
  fd @0 :Fd;
  type @1 :FileMonitorType;
  union {
    mmap :group {
      dead @2 :Bool;
      device @3 :Device;
      inode @4 :Inode;
    }
    procFd :group {
      tid @5 :Tid;
      serial @6 :UInt32;
    }
    procMem :group {
      tid @7 :Tid;
      serial @8 :UInt32;
      execCount @9 :UInt32;
    }
    stdio @10 :Fd;
    procStat @11 :Data;
    bpf :group {
      keySize @12: UInt64;
      valueSize @13 :UInt64;
    }
  }
}

struct KernelMapping {
  start @0 :RemotePtr;
  end @1 :RemotePtr;
  fsname @2 :CString;
  device @3 :Device;
  inode @4 :Inode;
  protection @5 :Int32;
  flags @6 :Int32;
  offset @7 :UInt64;
  mapType :union {
    file :group { # mapping of a file
      contentsPath @8 :Path;
    }
    guardSegment @9 :Void; # Empty map segment, PROT NONE, no pages in physical memory, no fsname
    # Mapping types below can all be compressed, as they need to be copied into the mapping anyhow
    sharedAnon :group {
      contentsPath @10 :Path;
      isSysVSegment @11 :Bool; # if we're a SysV, we need to set AddressSpace::shm_sizes[start] = size;
    }
    privateAnon :group { # e.g. stack, heap, etc
      contentsPath @12 :Path;
    }
    syscallBuffer :group {
      contentsPath @13 :Path;
    }
    rrPage :group {
      contentsPath @14 :Path;
    }
  }
}

# For lack of a better name.
struct ProcessSpace {
  virtualAddressSpace @0 :List(KernelMapping);
  breakpointFaultAddress @1 :RemotePtr;
  exe @2 :Data; # actual binary image exec'ed.
  originalExe @3 :Data; # original binary image executed during record
  monitors @4 :List(FileMonitor);
  taskFirstRunEvent @5 :FrameTime;
  vmFirstRunEvent @6 :FrameTime;
}

struct CapturedState {
  ticks @0 :Ticks;
  regs @1 :Registers;
  extraRegs @2 :ExtraRegisters;
  prname @3 :Data;
  fdtableIdentity @4 :UInt64;
  syscallbufChild @5 :RemotePtr;
  syscallbufSize @6 :UInt64;
  numSyscallbufBytes @7 :UInt64;
  preloadGlobals @8 :RemotePtr;
  scratchPtr @9 :RemotePtr;
  scratchSize @10 :UInt64;
  topOfStack @11 :RemotePtr;
  rseqState :group {
    ptr @12 :RemotePtr;
    abortPrefixSignature @13 :UInt32;
  }
  clonedFileDataOffset @14 :UInt64;
  threadLocals @15 :Data;
  recTid @16 :Tid;
  ownNamespaceRecTid @17 :Tid;
  serial @18 :UInt32;
  tguid :group {
    tid @19 :Tid;
    serial @20 :UInt32;
  }
  deschedFdChild @21 :Int32;
  clonedFileDataFdChild @22 :Int32;
  clonedFileDataFname @23 :Data;
  waitStatus @24 :Int32;
  tlsRegister @25 :UInt64;
  threadAreas @26 :List(Data); # std::vector<X86Arch::user_desc>
}

struct CapturedMemory {
  startAddress @0 :RemotePtr;
  data @1 :Data;
}

struct AddressSpaceClone {
  processSpace @0 :ProcessSpace;
  cloneLeaderState @1 :CapturedState;
  memberState @2 :List(CapturedState);
  capturedMemory @3 :List(CapturedMemory);
  auxv @4 :Data;
  # We need to know how to reconstitute the Register/ExtraRegister's in CapturedState
  arch @5 :Arch;
}

struct CloneCompletionInfo {
  addressSpaces @0 :List(AddressSpaceClone);
  sessionCurrentStep @1: Data;
  lastSigInfo @2 :Data;
  usesSyscallBuffering @3 :Bool;
}

# Marks are kind of tricky to represents as serialized data, but this amounts to
# a flattened Mark / InternalMark / ProtoMark
struct MarkData {
  time @0 :FrameTime;
  ticks @1 :Ticks;
  ticksAtEventStart @2 :Ticks;
  stepKey @3 :Int32;
  regs @4: Registers;
  returnAddresses @5 :List(RemotePtr);
  extraRegs @6: ExtraRegisters;
  singlestepToNextMarkNoSignal @7 :Bool;
  # The arch required to configure regs and extraRegs with the peristed data
  arch @8 :Arch;
}


# A serialized checkpoint
struct CheckpointInfo {
  cloneCompletion @0 :CloneCompletionInfo;
  id @1 :UInt64;
  lastContinueTask @2 :ExtendedTaskId;
  where @3 :Data;
  nextSerial @4 :UInt32; # next_serial_ value in Session.
  union {
    nonExplicit :group {
      # The mark which has the actual clone data we have serialized
      cloneMark @5 :MarkData;
      # The actual mark for the checkpoint, to which we replay-seek-to
      checkpointMark @6 :MarkData;
    }
    explicit @7 :MarkData;
  }
  # we need this data, to determine Progress, to be able to use them as reverse-exec
  statistics :group {
    bytesWritten @8 :UInt64;
    ticksProcessed @9 :Ticks;
    syscallsPerformed @10 :UInt32;
  }
}