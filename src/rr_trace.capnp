@0xcaa0b1486c12c629;

using Cxx = import "/capnp/c++.capnp";
$Cxx.namespace("rr::trace");

# We generally use Data instead of Text because for e.g. files there is no
# guarantee the data are valid UTF-8.
# We use the natural system types whenever possible. For example, even though
# negative fds are not possible, we use Int32 for fds to match kernel/library
# APIs.
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
  uuid @0 :Data;
  bindToCpu @1 :Int32;
  hasCpuidFaulting @2 :Bool;
  cpuidRecords @3 :Data;
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
