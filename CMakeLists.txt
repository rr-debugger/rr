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
set(rr_VERSION_MAJOR 2)
set(rr_VERSION_MINOR 0)
set(rr_VERSION_PATCH 0)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pthread -O0 -g3 -Wall -Werror -Wstrict-prototypes")
# Define __STDC_LIMIT_MACROS so |#include <stdint.h>| works as expected.
# Define __STDC_FORMAT_MACROS so |#include <inttypes.h>| works as expected.
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -D__STDC_LIMIT_MACROS -D__STDC_FORMAT_MACROS -std=c++0x -pthread -O0 -g3 -Wall -Werror")
set(CMAKE_ASM_FLAGS "${CMAKE_ASM_FLAGS} -g3")

option(force64bit, "Force a 64-bit build, rather than a 32-bit one")
if(force64bit)
  set(rr_MBITNESS_OPTION -m64)
else()
  set(rr_MBITNESS_OPTION -m32)
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${rr_MBITNESS_OPTION}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${rr_MBITNESS_OPTION}")
set(CMAKE_ASM_FLAGS "${CMAKE_ASM_FLAGS} ${rr_MBITNESS_OPTION}")

set_source_files_properties(src/preload/preload.c PROPERTIES COMPILE_FLAGS -O2)

# 32-bit rr requires its librrpreload to be compiled as position dependent code.
# 64-bit rr seems to not care so far.
#
# Use a dummy header to make the macro happy.
INCLUDE(CheckSymbolExists)
CHECK_SYMBOL_EXISTS(__i386__ stdint.h rr_DEFAULT_32BIT)

if (rr_DEFAULT_32BIT)
  # Disable PIC.
  string(REGEX REPLACE "-fPIC" ""
    CMAKE_SHARED_LIBRARY_C_FLAGS "${CMAKE_SHARED_LIBRARY_C_FLAGS}")
endif()

include_directories("${PROJECT_SOURCE_DIR}/include")
# We need to know where our generated files are.
include_directories("${CMAKE_CURRENT_BINARY_DIR}")

add_library(rrpreload
  src/preload/preload.c
  src/preload/traced_syscall.S
  src/preload/untraced_syscall.S
  src/preload/vsyscall_hook.S
)

# Ensure that CMake knows about our generated files.
#
# Alphabetical, please.
set(GENERATED_FILES
  AssemblyTemplates.generated
  CheckSyscallNumbers.generated
  IsAlwaysEmulatedSyscall.generated
  SyscallDefsTable.generated
  SyscallEnumsX64.generated
  SyscallEnumsX86.generated
  SyscallHelperFunctions.generated
  SyscallnameArch.generated
  SyscallRecordCase.generated
)

foreach(generated_file ${GENERATED_FILES})
  set_source_files_properties(${generated_file}
                              PROPERTIES GENERATED HEADER_FILE_ONLY)
  add_custom_command(OUTPUT ${generated_file}
                     COMMAND python "${CMAKE_CURRENT_SOURCE_DIR}/src/generate_syscalls.py"
		               "${CMAKE_CURRENT_BINARY_DIR}/${generated_file}"
		     DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/src/generate_syscalls.py"
		       "${CMAKE_CURRENT_SOURCE_DIR}/src/syscalls.py"
		       "${CMAKE_CURRENT_SOURCE_DIR}/src/assembly_templates.py")
endforeach(generated_file)

add_executable(rr
  ${GENERATED_FILES}
  src/test/cpuid_loop.S
  src/AddressSpace.cc
  src/AutoRemoteSyscalls.cc
  src/CompressedReader.cc
  src/CompressedWriter.cc
  src/CPUIDBugDetector.cc
  src/DiversionSession.cc
  src/EmuFs.cc
  src/Event.cc
  src/ExtraRegisters.cc
  src/Flags.cc
  src/GdbConnection.cc
  src/GdbServer.cc
  src/kernel_abi.cc
  src/kernel_metadata.cc
  src/log.cc
  src/main.cc
  src/PerfCounters.cc
  src/recorder.cc
  src/RecordSession.cc
  src/record_signal.cc
  src/record_syscall.cc
  src/Registers.cc
  src/replayer.cc
  src/ReplaySession.cc
  src/replay_syscall.cc
  src/Scheduler.cc
  src/Session.cc
  src/task.cc
  src/TraceFrame.cc
  src/TraceStream.cc
  src/util.cc
)

target_link_libraries(rr
  -ldl
  -lrt
  -lz
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
  async_segv_ignored
  at_threadexit
  bad_ip
  barrier
  big_buffers
  block
  blocked_sigsegv
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
  grandchild_threads
  grandchild_threads_main_running
  grandchild_threads_thread_running
  grandchild_threads_parent_alive
  ignored_sigsegv
  int3
  intr_futex_wait_restart
  intr_poll
  intr_read_no_restart
  intr_read_restart
  intr_sleep
  intr_sleep_no_restart
  io
  legacy-ugid
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
  sched_yield_to_lower_priority
  scm_rights
  sendfile
  setsid
  sigaction_old
  sigchld_interrupt_signal
  sigill
  sigprocmask
  sigqueueinfo
  sigreturn
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
  times
  tiocgwinsz
  truncate
  uname
  unjoined_thread
  wait
  write_race
  zero_length_read
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
  async_kill_with_threads
  async_kill_with_threads_main_running
  async_kill_with_threads_thread_running
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
  restart_abnormal_exit
  segfault
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
  break_rdtsc
  break_sigreturn
  break_sync_signal
  break_thread
  break_time_slice
  call_exit
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
  signal_checkpoint
  step1
  step_signal
  subprocess_exit_ends_session
  syscallbuf_timeslice_250
  trace_version
  term_trace_cpu
  term_trace_syscall
)

foreach(test ${BASIC_TESTS} ${TESTS_WITH_PROGRAM})
  add_executable(${test} src/test/${test}.c)
  target_link_libraries(${test} -lrt)
endforeach(test)

# cpuid test needs to link with cpuid_loop.S
add_executable(cpuid src/test/cpuid.c src/test/cpuid_loop.S)
target_link_libraries(cpuid -lrt)

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
if(${CMAKE_SYSTEM_PROCESSOR} STREQUAL "x86_64")
  set(CPACK_DEBIAN_PACKAGE_ARCHITECTURE "amd64")
elseif(${CMAKE_SYSTEM_PROCESSOR} MATCHES "i.86")
  set(CPACK_DEBIAN_PACKAGE_ARCHITECTURE "i386")
elseif(${CMAKE_SYSTEM_PROCESSOR} MATCHES "arm.*")
  set(CPACK_DEBIAN_PACKAGE_ARCHITECTURE "arm")
endif()

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
