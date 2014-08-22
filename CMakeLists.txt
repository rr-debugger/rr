# *-* Mode: cmake; *-*

cmake_minimum_required(VERSION 2.8.5)
project(rr C CXX ASM)

enable_testing()
set(BUILD_SHARED_LIBS ON)

set(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)
set(LIBRARY_OUTPUT_PATH ${PROJECT_BINARY_DIR}/lib)

# CAREFUL!  "-" is an invalid character in RPM package names, while
# debian is happy with it.  However, "_" is illegal in debs, while RPM
# is cool with it.  Sigh.
set(rr_VERSION_MAJOR 1)
set(rr_VERSION_MINOR 5)
set(rr_VERSION_PATCH 0)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pthread -O0 -g3 -Wall -Werror -m32 -Wstrict-prototypes")
# Define __STDC_FORMAT_MACROS so |#include <inttypes.h>| works as expected.
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -D__STDC_FORMAT_MACROS -std=c++0x -pthread -O0 -g3 -Wall -Werror -m32")
set(CMAKE_ASM_FLAGS "${CMAKE_ASM_FLAGS} -g3 -m32")

set_source_files_properties(src/preload/preload.c PROPERTIES COMPILE_FLAGS -O2)

# Disable PIC.
string(REGEX REPLACE "-fPIC" ""
  CMAKE_SHARED_LIBRARY_C_FLAGS "${CMAKE_SHARED_LIBRARY_C_FLAGS}")

include_directories("${PROJECT_SOURCE_DIR}/include")

add_library(rrpreload
  src/preload/preload.c
  src/preload/traced_syscall.S
  src/preload/untraced_syscall.S
  src/preload/vsyscall_hook.S
)

add_executable(rr
  src/test/cpuid_loop.S
  src/debugger_gdb.cc
  src/diverter.cc
  src/emufs.cc
  src/event.cc
  src/hpc.cc
  src/main.cc
  src/recorder.cc
  src/recorder_sched.cc
  src/record_signal.cc
  src/record_syscall.cc
  src/registers.cc
  src/remote_syscalls.cc
  src/replayer.cc
  src/replay_syscall.cc
  src/session.cc
  src/syscalls.cc
  src/task.cc
  src/trace.cc
  src/util.cc
  src/vm.cc
)

target_link_libraries(rr
  -ldl
  -lrt
)

target_link_libraries(rrpreload
  -ldl
)

install(PROGRAMS scripts/signal-rr-recording.sh
  DESTINATION bin)

install(TARGETS rr rrpreload
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib)

##--------------------------------------------------
## Testing

# A "basic test" consists of a foo.c source file. All basic tests use the
# same basic_test.run driver script. The test name is passed as an additional
# parameter to the driver script. This script just does
# "compare_test EXIT-SUCCESS", i.e. records and replays the program and verifies
# that the output of both runs is identical and contains EXIT-SUCCESS.
#
# NB: you must update this variable when adding a new test source
# file.  The list is not generated automatically.
#
# Alphabetical, please.
set(BASIC_TESTS
  64bit_child
  accept
  at_threadexit
  bad_ip
  barrier
  big_buffers
  block
  chew_cpu
  clock
  clone
  desched_blocking_poll
  epoll_create
  epoll_create1
  exec_self
  fadvise
  fault_in_code_page
  fcntl_owner_ex
  flock
  fork_child_crash
  fork_stress
  fxregs
  getgroups
  getsid
  int3
  intr_futex_wait_restart
  intr_poll
  intr_read_no_restart
  intr_read_restart
  intr_sleep
  intr_sleep_no_restart
  io
  madvise
  map_fixed
  mmap_discontinuous
  mmap_private
  mmap_ro
  mmap_shared
  mmap_shared_subpage
  mmap_short_file
  mmap_tmpfs
  mprotect
  mprotect_heterogenous
  mprotect_stack
  mremap
  msg
  msync
  munmap_discontinuous
  no_mask_timeslice
  orphan_process
  pause
  perf_event
  poll_sig_race
  prctl
  prctl_name
  prw
  pthread_condvar_locking
  rdtsc
  save_data_fd
  sched_setaffinity
  sched_yield
  scm_rights
  sendfile
  setsid
  sigchld_interrupt_signal
  sigprocmask
  sigqueueinfo
  sigrt
  sigtrap
  simple
  sioc
  splice
  statfs
  strict_priorities
  switch_read
  syscallbuf_timeslice
  sysconf
  sysctl
  sysemu_singlestep
  tcgets
  tgkill
  thread_stress
  timerfd
  tiocgwinsz
  truncate
  uname
  unjoined_thread
  wait
  write_race
)

# A "test with program" consists of a foo.c source file and a foo.run driver
# script.  See src/test/util.sh to learn how the .run files work.
#
# NB: you must update this variable when adding a new test source
# file.  The list is not generated automatically.
#
# Alphabetical, please.
set(TESTS_WITH_PROGRAM
  abort_nonmain
  alarm
  args
  async_segv
  async_signal_syscalls
  async_signal_syscalls_siginfo
  async_usr1
  bad_syscall
  block_intr_sigchld
  breakpoint
  breakpoint_overlap
  call_function
  condvar_stress
  crash
  exit_group
  exit_status
  explicit_checkpoints
  fork_syscalls
  getcwd
  goto_event
  hello
  ignored_async_usr1
  immediate_restart
  interrupt
  intr_ptrace_decline
  link
  mmap_write
  mutex_pi_stress
  nanosleep
  priority
  ptrace
  read_big_struct
  segfault
  sigill
  step_thread
  target_fork
  target_process
  term_nonmain
  threaded_syscall_spam
  threads
  tiocinq
  user_ignore_sig
  vfork
  watchpoint
)

# A "test without program" is a foo.run driver script only, which does
# something with one of the test executables above (or has special rules
# to build its own executable).
#
# NB: you must update this variable when adding a new test source
# file.  The list is not generated automatically.
#
# Alphabetical, please.
set(TESTS_WITHOUT_PROGRAM
  async_signal_syscalls_100
  async_signal_syscalls_1000
  bad_breakpoint
  break_block
  break_clock
  break_clone
  break_exec
  break_int3
  break_mmap_private
  break_msg
  break_ptrace
  break_rdtsc
  break_sigreturn
  break_sync_signal
  break_thread
  break_time_slice
  checkpoint_async_signal_syscalls_1000
  checkpoint_mmap_shared
  checkpoint_prctl_name
  checkpoint_simple
  cont_signal
  cpuid
  dead_thread_target
  deliver_async_signal_during_syscalls
  env_newline
  execp
  explicit_checkpoint_clone
  fork_exec_info_thr
  get_thread_list
  parent_no_break_child_bkpt
  parent_no_stop_child_crash
  read_bad_mem
  remove_watchpoint
  restart_unstable
  restart_diversion
  sanity
  signal_stop
  step1
  step_signal
  subprocess_exit_ends_session
  syscallbuf_timeslice_250
  trace_version
  term_trace_cpu
  term_trace_syscall
)

# An "other test" is a test which doesn't have its own driver script but
# needs its own rules for building an executable so can't be in BASIC_TESTS.
#
# NB: you must update this variable when adding a new test source
# file.  The list is not generated automatically.
#
# Alphabetical, please.
set(OTHER_TESTS
  sigreturn
)

foreach(test ${BASIC_TESTS} ${TESTS_WITH_PROGRAM})
  add_executable(${test} src/test/${test}.c)
  target_link_libraries(${test} -lrt)
endforeach(test)

# cpuid test needs to link with cpuid_loop.S
add_executable(cpuid src/test/cpuid.c src/test/cpuid_loop.S)
target_link_libraries(cpuid -lrt)

# sigreturn test needs to link with sigreturn_helper.S
add_executable(sigreturn src/test/sigreturn.c src/test/sigreturn_helper.S)
target_link_libraries(sigreturn -lrt)

foreach(test ${BASIC_TESTS} ${OTHER_TESTS})
  add_test(${test}
    bash ${CMAKE_SOURCE_DIR}/src/test/basic_test.run -b ${PROJECT_BINARY_DIR} ${test})
  set_tests_properties(${test}
    PROPERTIES FAIL_REGULAR_EXPRESSION "FAILED")

  add_test(${test}-no-syscallbuf
    bash ${CMAKE_SOURCE_DIR}/src/test/basic_test.run -n ${PROJECT_BINARY_DIR} ${test})
  set_tests_properties(${test}-no-syscallbuf
    PROPERTIES FAIL_REGULAR_EXPRESSION "FAILED")
endforeach(test)

foreach(test ${TESTS_WITH_PROGRAM} ${TESTS_WITHOUT_PROGRAM})
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
set(CPACK_PACKAGE_DESCRIPTION_FILE "${CMAKE_SOURCE_DIR}/README.md")
set(CPACK_PACKAGE_VENDOR "Mozilla Foundation")

set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Mozilla Foundation")
set(CPACK_DEBIAN_PACKAGE_SECTION "devel")

# XXX Cmake 2.8.7 doesn't know how to avoid specifiying /usr,
# /usr/bin, etc, as files to be installed, but distros are finicky
# about their specification.  We want to manually filter those paths
# out of our install list but 2.8.7 also isn't capable of that.
set(CPACK_RPM_USER_BINARY_SPECFILE "${CMAKE_SOURCE_DIR}/rr.spec")
set(CPACK_RPM_PACKAGE_RELEASE 1)
set(CPACK_RPM_PACKAGE_GROUP "Development/Debuggers")
set(CPACK_RPM_PACKAGE_LICENSE "MIT and BSD")

include (CPack)

##--------------------------------------------------
## Misc

add_custom_target(setup-travis COMMAND src/script/setup_travis.sh)
