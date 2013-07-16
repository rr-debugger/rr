# *-* Mode: cmake; *-*

cmake_minimum_required(VERSION 2.8.5)
project(rr)

enable_testing()
set(BUILD_SHARED_LIBS ON)

set(PROJECT_BINARY_DIR ${CMAKE_SOURCE_DIR}/obj)
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)
set(LIBRARY_OUTPUT_PATH ${PROJECT_BINARY_DIR}/lib)

# CAREFUL!  "-" is an invalid character in RPM package names, while
# debian is happy with it.  However, "_" is illegal in debs, while RPM
# is cool with it.  Sigh.
set(rr_VERSION_MAJOR 0)
set(rr_VERSION_MINOR 1pre)
set(rr_VERSION_PATCH 0)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pthread -O0 -g3 -Wall -Werror -m32")

# Disable PIC.
string(REGEX REPLACE "-fPIC" ""
  CMAKE_SHARED_LIBRARY_C_FLAGS "${CMAKE_SHARED_LIBRARY_C_FLAGS}")

add_library(rr_syscall_buffer
  src/share/syscall_buffer.c
)

add_executable(rr
  src/main.c
  src/recorder/handle_ioctl.c
  src/recorder/handle_signal.c
  src/recorder/rec_process_event.c
  src/recorder/rec_sched.c
  src/recorder/recorder.c
  src/replayer/dbg_gdb.c
  src/replayer/rep_process_event.c
  src/replayer/rep_sched.c
  src/replayer/replayer.c
  src/share/hpc.c
  src/share/ipc.c
  src/share/list.c
  src/share/shmem.c
  src/share/sys.c
  src/share/trace.c
  src/share/util.c
)

# TODO remove this when we can manage pfm and disasm dependencies
# properly
target_link_libraries(rr
  libpfm.a
  libdisasm.a
)

install(TARGETS rr rr_syscall_buffer
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib)

# TODO: manage building C test files with the build system
set(RR_TEST_CMD_COMMON
  "${CMAKE_SOURCE_DIR}/src/script/test.sh" "-dir=${CMAKE_SOURCE_DIR}/src/test" "-rr=${EXECUTABLE_OUTPUT_PATH}/rr")

add_test(Tests ${RR_TEST_CMD_COMMON} -lib=y)
set_tests_properties(Tests
  PROPERTIES FAIL_REGULAR_EXPRESSION "FAILED")

add_test(TestsNoFilterLib ${RR_TEST_CMD_COMMON} -lib=n)
set_tests_properties(TestsNoFilterLib
  PROPERTIES FAIL_REGULAR_EXPRESSION "FAILED")

# Why isn't dumping output on failure default ...
add_custom_target(check COMMAND ${CMAKE_CTEST_COMMAND} --verbose)

add_custom_target(setup-travis COMMAND src/script/setup_travis.sh)

# Package configuration
include (InstallRequiredSystemLibraries)

set(CPACK_PACKAGE_NAME "rr")
set(CPACK_PACKAGE_VERSION_MAJOR "${rr_VERSION_MAJOR}")
set(CPACK_PACKAGE_VERSION_MINOR "${rr_VERSION_MINOR}")
set(CPACK_PACKAGE_VERSION_PATCH "${rr_VERSION_PATCH}")
set(CPACK_SYSTEM_NAME "${CMAKE_SYSTEM_NAME}-${CMAKE_SYSTEM_PROCESSOR}")

set(CPACK_OUTPUT_FILE_PREFIX dist)
set(CPACK_GENERATOR "TGZ;RPM;DEB")
set(CPACK_SOURCE_GENERATOR "TGZ")
set(CPACK_BINARY_DIR "${CMAKE_SOURCE_DIR}")
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
