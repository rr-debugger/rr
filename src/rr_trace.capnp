@0xcaa0b1486c12c629;

using Cxx = import "/capnp/c++.capnp";
$Cxx.namespace("rr::trace");

struct Header {
  uuid @0 :Data;
  bindToCpu @1 :Int32;
  hasCpuidFaulting @2 :Bool;
  cpuidRecords @3 :Data;
}
