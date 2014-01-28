# *-* Mode: cmake; *-*

cmake_minimum_required(VERSION 2.8.5)
project(rr)

enable_testing()
set(BUILD_SHARED_LIBS ON)

set(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)
set(LIBRARY_OUTPUT_PATH ${PROJECT_BINARY_DIR}/lib)

# CAREFUL!  "-" is an invalid character in RPM package names, while
# debian is happy with it.  However, "_" is illegal in debs, while RPM
# is cool with it.  Sigh.
set(rr_VERSION_MAJOR 0)
set(rr_VERSION_MINOR 3pre)
set(rr_VERSION_PATCH 0)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pthread -O0 -g3 -Wall -Werror -m32 -Wstrict-prototypes")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++0x -pthread -O0 -g3 -Wall -Werror -m32")

# Disable PIC.
string(REGEX REPLACE "-fPIC" ""
  CMAKE_SHARED_LIBRARY_C_FLAGS "${CMAKE_SHARED_LIBRARY_C_FLAGS}")

include_directories("${PROJECT_SOURCE_DIR}/include")

add_library(rrpreload
  src/preload/preload.c
)

add_executable(rr
  src/main.cc
  src/recorder/handle_ioctl.cc
  src/recorder/handle_signal.cc
  src/recorder/rec_process_event.cc
  src/recorder/rec_sched.cc
  src/recorder/recorder.cc
  src/replayer/dbg_gdb.cc
  src/replayer/rep_process_event.cc
  src/replayer/replayer.cc
  src/share/hpc.cc
  src/share/ipc.cc
  src/share/shmem.cc
  src/share/sys.cc
  src/share/task.cc
  src/share/trace.cc
  src/share/util.cc
)

# TODO remove this when we can manage pfm and disasm dependencies
# properly
target_link_libraries(rr
  -lrt
  libpfm.a
  libdisasm.a
)

target_link_libraries(rrpreload
  -ldl
)

install(TARGETS rr rrpreload
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib)

##--------------------------------------------------
## Testing

# A "basic test" consists of a foo.c source file and a foo.run driver
# script.  See src/test/util.sh to learn how the .run files work.
#
# NB: you must update this variable when adding a new test source
# file.  The list is not generated automatically.
#
# Alphabetical, please.
set(BASIC_TESTS
  abort_nonmain
  accept
  alarm
  args
  async_segv
  async_signal_syscalls
  async_usr1
  at_threadexit
  bad_ip
  bad_syscall
  barrier
  big_buffers
  block
  breakpoint
  chew_cpu
  clock
  condvar_stress
  exit_group
  fadvise
  flock
  fork_syscalls
  hello
  ignored_async_usr1
  int3
  interrupt
  intr_futex_wait_restart
  intr_poll
  intr_ptrace_decline
  intr_read_no_restart
  intr_read_restart
  intr_sleep
  intr_sleep_no_restart
  io
  link
  madvise
  map_fixed
  mmap_discontinuous
  mmap_private
  mmap_ro
  mmap_shared
  mmap_shared_subpage
  mmap_tmpfs
  mmap_write
  mprotect
  mprotect_stack
  mremap
  nanosleep
  perf_event
  prctl
  prctl_name
  priority
  prw
  rdtsc
  save_data_fd
  sched_setaffinity
  segfault
  sigchld_interrupt_signal
  sigill
  sigprocmask
  sigrt
  sigtrap
  simple
  splice
  statfs
  step_thread
  switch_read
  syscallbuf_timeslice
  tcgets
  term_nonmain
  tgkill
  thread_stress
  threads
  tiocinq
  truncate
  uname
  user_ignore_sig
)

# A "custom test" is a foo.run driver script only, which does
# something with one of the basic-test executables above.
#
# NB: you must update this variable when adding a new test source
# file.  The list is not generated automatically.
#
# Alphabetical, please.
set(CUSTOM_TESTS
  async_signal_syscalls_100
  async_signal_syscalls_1000
  break_clock
  break_int3
  break_mmap_private
  break_rdtsc
  break_sync_signal
  break_thread
  break_time_slice
  cont_signal
  dead_thread_target
  deliver_async_signal_during_syscalls
  execp
  get_thread_list
  read_bad_mem
  sanity
  signal_stop
  step1
  step_signal
  syscallbuf_timeslice_250
  term_trace_cpu
  term_trace_syscall
)

foreach(test ${BASIC_TESTS})
  add_executable(${test} src/test/${test}.c)
  target_link_libraries(${test} -lrt)
endforeach(test)

foreach(test ${BASIC_TESTS} ${CUSTOM_TESTS})
  add_test(${test}
    bash ${CMAKE_SOURCE_DIR}/src/test/${test}.run -b ${PROJECT_BINARY_DIR})
  set_tests_properties(${test}
    PROPERTIES FAIL_REGULAR_EXPRESSION "FAILED")

  add_test(${test}-no-syscallbuf
    bash ${CMAKE_SOURCE_DIR}/src/test/${test}.run -n ${PROJECT_BINARY_DIR})
  set_tests_properties(${test}-no-syscallbuf
    PROPERTIES FAIL_REGULAR_EXPRESSION "FAILED")
endforeach(test)

include(ProcessorCount)
ProcessorCount(N)
if(NOT N EQUAL 0)
  set(JFLAG -j${N})
endif()

add_custom_target(check COMMAND ${CMAKE_CTEST_COMMAND} --verbose ${JFLAG})

##--------------------------------------------------
## Package configuration

include (InstallRequiredSystemLibraries)

set(CPACK_PACKAGE_NAME "rr")
set(CPACK_PACKAGE_VERSION_MAJOR "${rr_VERSION_MAJOR}")
set(CPACK_PACKAGE_VERSION_MINOR "${rr_VERSION_MINOR}")
set(CPACK_PACKAGE_VERSION_PATCH "${rr_VERSION_PATCH}")
set(CPACK_SYSTEM_NAME "${CMAKE_SYSTEM_NAME}-${CMAKE_SYSTEM_PROCESSOR}")

set(CPACK_OUTPUT_FILE_PREFIX dist)
set(CPACK_GENERATOR "TGZ;RPM;DEB")
set(CPACK_SOURCE_GENERATOR "TGZ")
set(CPACK_BINARY_DIR "${PROJECT_BINARY_DIR}")
set(CPACK_STRIP_FILES TRUE)

set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_SOURCE_DIR}/LICENSE")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY
  "Lightweight tool for recording and replaying execution of applications (trees of processes and threads)")
set(CPACK_PACKAGE_DESCRIPTION_FILE "${CMAKE_SOURCE_DIR}/README")
set(CPACK_PACKAGE_VENDOR "Mozilla Foundation")

set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Mozilla Foundation")
set(CPACK_DEBIAN_PACKAGE_SECTION "devel")
#set(CPACK_DEBIAN_PACKAGE_DEPENDS "pfm, disasm")

# XXX Cmake 2.8.7 doesn't know how to avoid specifiying /usr,
# /usr/bin, etc, as files to be installed, but distros are finicky
# about their specification.  We want to manually filter those paths
# out of our install list but 2.8.7 also isn't capable of that.
set(CPACK_RPM_USER_BINARY_SPECFILE "${CMAKE_SOURCE_DIR}/rr.spec")
set(CPACK_RPM_PACKAGE_RELEASE 1)
set(CPACK_RPM_PACKAGE_GROUP "Development/Debuggers")
set(CPACK_RPM_PACKAGE_LICENSE "MIT and BSD")
#set(CPACK_RPM_PACKAGE_REQUIRES "Requires: pfm, disasm")

include (CPack)

##--------------------------------------------------
## Misc

add_custom_target(setup-travis COMMAND src/script/setup_travis.sh)
