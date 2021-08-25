# *-* Mode: cmake; *-*

cmake_minimum_required(VERSION 3.1.0)
project(rr C CXX ASM)

# "Do not add flags to export symbols from executables without the ENABLE_EXPORTS target property."
# This avoids linking executables with -rdynamic. -rdynamic has been observed
# to cause rr_exec_stub to be linked with the dynamic linker with some
# version(s) of clang (but linked to an incorrect file name, causing
# exec of rr_exec_stub to fail).
if(POLICY CMP0065)
  cmake_policy(SET CMP0065 NEW)
endif()

# On single configuration generators, make Debug the default configuration
if(NOT CMAKE_CONFIGURATION_TYPES)
  if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Debug" CACHE STRING "Whether to build in `Debug` or `Release` mode." FORCE)
  endif()
endif()

enable_testing()
set(BUILD_SHARED_LIBS ON)

set(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/lib/rr)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(BUILD_TESTS ON CACHE BOOL "Build tests")
set(WILL_RUN_TESTS ${BUILD_TESTS} CACHE BOOL "Run tests")
option(INSTALL_TESTSUITE "Install the testsuite")

# CAREFUL!  "-" is an invalid character in RPM package names, while
# debian is happy with it.  However, "_" is illegal in debs, while RPM
# is cool with it.  Sigh.
set(rr_VERSION_MAJOR 5)
set(rr_VERSION_MINOR 4)
set(rr_VERSION_PATCH 0)

add_definitions(-DRR_VERSION="${rr_VERSION_MAJOR}.${rr_VERSION_MINOR}.${rr_VERSION_PATCH}")

execute_process(
  COMMAND git rev-parse HEAD
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
  OUTPUT_VARIABLE GIT_REVISION
  OUTPUT_STRIP_TRAILING_WHITESPACE
)
configure_file(
  ${CMAKE_SOURCE_DIR}/src/git_revision.h.in
  ${CMAKE_BINARY_DIR}/git_revision.h
)

set(FLAGS_COMMON "-D__USE_LARGEFILE64 -pthread")
set(supports32bit true)
set(x86ish false)
if (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "aarch64")
  set(supports32bit false)
  set(FLAGS_COMMON "${FLAGS_COMMON} -march=armv8.3-a -Wl,-dynamic-linker=/lib/aarch64-linux-gnu/atomics/ld-linux-aarch64.so.1")
else()
  set(x86ish true)
  set(FLAGS_COMMON "${FLAGS_COMMON} -msse2 -D__MMX__ -D__SSE__ -D__SSE2__")
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${FLAGS_COMMON} -Wstrict-prototypes -std=gnu11")
# Define __STDC_LIMIT_MACROS so |#include <stdint.h>| works as expected.
# Define __STDC_FORMAT_MACROS so |#include <inttypes.h>| works as expected.
include(CheckCXXCompilerFlag)
CHECK_CXX_COMPILER_FLAG("-std=c++14" SUPPORTS_CXX14)
if (SUPPORTS_CXX14)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${FLAGS_COMMON} -D__STDC_LIMIT_MACROS -D__STDC_FORMAT_MACROS -std=c++14")
else()
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${FLAGS_COMMON} -D__STDC_LIMIT_MACROS -D__STDC_FORMAT_MACROS -std=c++11")
endif()

# We support three build types:
# DEBUG: suitable for debugging rr
# RELEASE: suitable for using rr in production (but keeps rr debuginfo)
# OTHER: suitable for using rr in production, but honouring distro/user opt/debug settings
# (which we assume are suitable for production use)

# Base settings for debug and release/unspecified builds.
# Use -Werror for debug builds because we assume a developer is building, not a user.
set(RR_FLAGS_DEBUG "-Wall -Wextra -DDEBUG -UNDEBUG")
set(RR_FLAGS_RELEASE "-Wall -Wextra -UDEBUG -DNDEBUG")

# The folowing settings are the defaults for the OTHER build type.
# Flags used to build the preload library. MUST have debuginfo enabled. SHOULD be optimized.
set(PRELOAD_COMPILE_FLAGS "${RR_FLAGS_RELEASE} -fno-stack-protector -g3 -U_FORTIFY_SOURCE")
# Flags used to build Brotli. SHOULD be optimized. MUST NOT error on warnings.
set(BROTLI_COMPILE_FLAGS ${RR_FLAGS_RELEASE})
# Flags used to build tests. MUST have -DDEBUG and debuginfo enabled, MUST NOT be optimized.
set(RR_TEST_FLAGS "${RR_FLAGS_DEBUG} -g3 -O0")
# Flags used to build other files. Entirely build-type-dependent.
set(RR_FLAGS ${RR_FLAGS_RELEASE})

# Now override for build type.
string(TOLOWER ${CMAKE_BUILD_TYPE} LOWERCASE_CMAKE_BUILD_TYPE)
if(LOWERCASE_CMAKE_BUILD_TYPE STREQUAL "debug")
  set(PRELOAD_COMPILE_FLAGS "${PRELOAD_COMPILE_FLAGS} -O2 -Werror")
  set(BROTLI_COMPILE_FLAGS "${RR_FLAGS_RELEASE} -O2")
  set(RR_TEST_FLAGS "${RR_TEST_FLAGS} -Werror")
  set(RR_FLAGS "${RR_FLAGS_DEBUG} -g3 -Werror")
elseif(LOWERCASE_CMAKE_BUILD_TYPE STREQUAL "release")
  # CMake itself will add optimization flags
  set(RR_FLAGS "${RR_FLAGS_RELEASE} -g3 -flto")
endif()

set(LINKER_FLAGS "")
if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
  # Gcc generates bogus R_386_GOTOFF relocations in .debug_info which
  # lld 9 rejects
  set(LINKER_FLAGS "-fuse-ld=bfd")
endif()

if(CMAKE_C_COMPILER_ID STREQUAL "Clang")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-unused-command-line-argument")
endif()
if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-unused-command-line-argument")
endif()
if (CMAKE_ASM_COMPILER_ID STREQUAL "Clang")
  set(CMAKE_ASM_FLAGS "${CMAKE_ASM_FLAGS} -fno-integrated-as")
endif()

option(force32bit "Force a 32-bit rr build, rather than both 64 and 32-bit. rr will only be able to record and replay 32-bit processes.")
option(disable32bit "On a 64-bit platform, avoid requiring a 32-bit cross-compilation toolchain by not building 32-bit components. rr will be able to record 32-bit processes but not replay them.")

if(force32bit)
  set(rr_32BIT true)
  set(rr_64BIT false)
  set(rr_MBITNESS_OPTION -m32)
else()
  if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    if(disable32bit OR NOT supports32bit)
      set(rr_32BIT false)
    else()
      set(rr_32BIT true)
    endif()
    set(rr_64BIT true)
  else()
    set(rr_32BIT true)
    set(rr_64BIT false)
  endif()
  set(rr_MBITNESS_OPTION)
endif()

option(staticlibs "Force usage of static linkage for non-standard libraries like capnproto")

# Check that compiling 32-bit code on a 64-bit target works, if required.
if(CMAKE_HOST_SYSTEM_PROCESSOR STREQUAL "x86_64" AND rr_32BIT)
  # try_compile won't accept LINK_FLAGS, so do this manually.
  file(WRITE "${CMAKE_BINARY_DIR}/test32.c" "int main() { return 0; }")
  execute_process(COMMAND ${CMAKE_C_COMPILER} -o ${CMAKE_BINARY_DIR}/test32 ${CMAKE_BINARY_DIR}/test32.c -m32
                  RESULT_VARIABLE COMPILER_32BIT_RESULT)
  if(NOT (COMPILER_32BIT_RESULT EQUAL 0))
    message(FATAL_ERROR "Your toolchain doesn't support 32-bit cross-compilation. Install the required packages or pass -Ddisable32bit=ON to cmake.")
  endif()
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${rr_MBITNESS_OPTION}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${rr_MBITNESS_OPTION}")
set(CMAKE_ASM_FLAGS "${CMAKE_ASM_FLAGS} ${rr_MBITNESS_OPTION}")

find_package(PkgConfig REQUIRED)

# If we're cross-compiling a 32-bit rr build on a 64-bit host we need
# to ensure we're looking for the right libraries.
# This has been tested on Ubuntu and Fedora.
if(CMAKE_HOST_SYSTEM_PROCESSOR STREQUAL "x86_64" AND NOT rr_64BIT)
  set(LIBDIR32_CANDIDATES
    /usr/lib/i386-linux-gnu/pkgconfig/
    /usr/lib/pkgconfig/
  )
  foreach(libdir ${LIBDIR32_CANDIDATES})
    if(IS_DIRECTORY ${libdir})
      set(ENV{PKG_CONFIG_LIBDIR} ${libdir})
      break()
     endif()
   endforeach(libdir)
   if(NOT DEFINED ENV{PKG_CONFIG_LIBDIR})
     message(FATAL_ERROR "Couldn't find a suitable 32-bit pkgconfig lib dir. You probably need to install a 32-bit pkgconfig package (pkgconfig.i686 for Fedora or pkg-config:i386 for Ubuntu")
   endif()
endif()

find_program(CAPNP capnp)
if(${CAPNP} STREQUAL "CAPNP-NOTFOUND")
  message(FATAL_ERROR "Can't find 'capnp' command; install Capnproto packages? https://github.com/rr-debugger/rr/wiki/Building-And-Installing#tldr")
endif()

set(REQUIRED_LIBS
  capnp
)

foreach(required_lib ${REQUIRED_LIBS})
  string(TOUPPER ${required_lib} PKG)
  pkg_check_modules(${PKG} REQUIRED ${required_lib})
  if(staticlibs)
    string(REPLACE ";" " " ${PKG}_STATIC_CFLAGS "${${PKG}_STATIC_CFLAGS}")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${${PKG}_STATIC_CFLAGS}")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${${PKG}_STATIC_CFLAGS}")
  else()
    string(REPLACE ";" " " ${PKG}_CFLAGS "${${PKG}_CFLAGS}")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${${PKG}_CFLAGS}")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${${PKG}_CFLAGS}")
  endif()
endforeach(required_lib)

# ==== brotli ====
set(BROTLI_FILES
  third-party/brotli/common/dictionary.c
  third-party/brotli/common/transform.c
  third-party/brotli/dec/bit_reader.c
  third-party/brotli/dec/decode.c
  third-party/brotli/dec/huffman.c
  third-party/brotli/dec/state.c
  third-party/brotli/enc/backward_references.c
  third-party/brotli/enc/backward_references.h
  third-party/brotli/enc/backward_references_hq.c
  third-party/brotli/enc/backward_references_hq.h
  third-party/brotli/enc/backward_references_inc.h
  third-party/brotli/enc/bit_cost.c
  third-party/brotli/enc/bit_cost.h
  third-party/brotli/enc/bit_cost_inc.h
  third-party/brotli/enc/block_encoder_inc.h
  third-party/brotli/enc/block_splitter.c
  third-party/brotli/enc/block_splitter.h
  third-party/brotli/enc/block_splitter_inc.h
  third-party/brotli/enc/brotli_bit_stream.c
  third-party/brotli/enc/brotli_bit_stream.h
  third-party/brotli/enc/cluster.c
  third-party/brotli/enc/cluster.h
  third-party/brotli/enc/cluster_inc.h
  third-party/brotli/enc/command.h
  third-party/brotli/enc/compress_fragment.c
  third-party/brotli/enc/compress_fragment.h
  third-party/brotli/enc/compress_fragment_two_pass.c
  third-party/brotli/enc/compress_fragment_two_pass.h
  third-party/brotli/enc/context.h
  third-party/brotli/enc/dictionary_hash.c
  third-party/brotli/enc/dictionary_hash.h
  third-party/brotli/enc/encode.c
  third-party/brotli/enc/encoder_dict.c
  third-party/brotli/enc/entropy_encode.c
  third-party/brotli/enc/entropy_encode.h
  third-party/brotli/enc/entropy_encode_static.h
  third-party/brotli/enc/fast_log.h
  third-party/brotli/enc/find_match_length.h
  third-party/brotli/enc/hash_forgetful_chain_inc.h
  third-party/brotli/enc/hash.h
  third-party/brotli/enc/hash_longest_match64_inc.h
  third-party/brotli/enc/hash_longest_match_inc.h
  third-party/brotli/enc/hash_longest_match_quickly_inc.h
  third-party/brotli/enc/hash_to_binary_tree_inc.h
  third-party/brotli/enc/histogram.c
  third-party/brotli/enc/histogram.h
  third-party/brotli/enc/histogram_inc.h
  third-party/brotli/enc/literal_cost.c
  third-party/brotli/enc/literal_cost.h
  third-party/brotli/enc/memory.c
  third-party/brotli/enc/memory.h
  third-party/brotli/enc/metablock.c
  third-party/brotli/enc/metablock.h
  third-party/brotli/enc/metablock_inc.h
  third-party/brotli/enc/port.h
  third-party/brotli/enc/prefix.h
  third-party/brotli/enc/quality.h
  third-party/brotli/enc/ringbuffer.h
  third-party/brotli/enc/static_dict.c
  third-party/brotli/enc/static_dict.h
  third-party/brotli/enc/static_dict_lut.h
  third-party/brotli/enc/utf8_util.c
  third-party/brotli/enc/utf8_util.h
  third-party/brotli/enc/write_bits.h
)
add_library(brotli STATIC ${BROTLI_FILES})
set_source_files_properties(${BROTLI_FILES}
                            PROPERTIES COMPILE_FLAGS ${BROTLI_COMPILE_FLAGS})
# ==== brotli ====

find_path(SECCOMP NAMES "linux/seccomp.h")
if(NOT SECCOMP)
  message(FATAL_ERROR "Couldn't find linux/seccomp.h. You may need to upgrade your kernel.")
endif()

set(Python_ADDITIONAL_VERSIONS 3 3.8 3.7 3.6 3.5 3.4 3.3 3.2 3.1 3.0)
find_package(PythonInterp 3 REQUIRED)

execute_process(COMMAND "${PYTHON_EXECUTABLE}" "-c" "# nothing"
                RESULT_VARIABLE python_status)
if(python_status)
  message(FATAL_ERROR "Couldn't run python interpreter ${PYTHON_EXECUTABLE}.")
endif()

# Check for required Python modules
if(WILL_RUN_TESTS)
  if(NOT BUILD_TESTS)
    message(FATAL_ERROR "Running tests requires building them")
  endif()

  set(REQUIRED_PYTHON_MODULES
    pexpect
  )
else()
  set(REQUIRED_PYTHON_MODULES)
endif()

foreach(py_module ${REQUIRED_PYTHON_MODULES})
  execute_process(COMMAND "${PYTHON_EXECUTABLE}" "-c"
                  "import ${py_module}"
                  RESULT_VARIABLE module_status)
  if(module_status)
    message(FATAL_ERROR "Couldn't find required Python module ${py_module}.")
  endif()
endforeach(py_module)

if(WILL_RUN_TESTS)
  # Check for gdb
  execute_process(COMMAND "gdb" "--version" RESULT_VARIABLE module_status OUTPUT_QUIET)
  if(module_status)
    message(FATAL_ERROR "Couldn't find gdb.")
  endif()
endif()

include_directories("${PROJECT_SOURCE_DIR}/include")
include_directories("${PROJECT_SOURCE_DIR}/third-party/proc-service")
include_directories("${PROJECT_SOURCE_DIR}/third-party/brotli/include")
# We need to know where our generated files are.
include_directories("${CMAKE_CURRENT_BINARY_DIR}")

set(RR_PAGE_FILES
  rr_page.S
)
set(RR_PAGE_SOURCE_FILES
  ${RR_PAGE_FILES}
  rr_page_instructions.S
  rr_vdso.S
  rr_page.ld
)
add_library(rrpage)
foreach(file ${RR_PAGE_FILES})
  target_sources(rrpage PUBLIC "${CMAKE_SOURCE_DIR}/src/preload/${file}")
  set_source_files_properties("${CMAKE_SOURCE_DIR}/src/preload/${file}"
                              PROPERTIES COMPILE_FLAGS ${PRELOAD_COMPILE_FLAGS})
endforeach(file)

# Since librrpage replaces the kernel vDSO for processes exec'd by rr,
# we want it to have the same SONAME as the real vDSO to trick things
# like AddressSanitizer into recognising it as the vDSO.
set_target_properties(rrpage PROPERTIES NO_SONAME ON)
set_target_properties(rrpage PROPERTIES LINK_FLAGS "-Wl,-T -Wl,${CMAKE_SOURCE_DIR}/src/preload/rr_page.ld -Wl,--hash-style=both -nostartfiles -nostdlib -Wl,-z,max-page-size=0x1000 -Wl,-soname,linux-vdso.so.1 ${LINKER_FLAGS}")
set_target_properties(rrpage PROPERTIES LINK_DEPENDS ${CMAKE_SOURCE_DIR}/src/preload/rr_page.ld)
# CMake seems to have trouble generating the link line without this
set_target_properties(rrpage PROPERTIES LINKER_LANGUAGE C)

add_custom_command(TARGET rrpage POST_BUILD
                   COMMAND ${CMAKE_SOURCE_DIR}/src/preload/tweak_librrpage.py $<TARGET_FILE:rrpage>)

# Order matters here! syscall_hook.S must be immediately before syscallbuf.c,
# raw_syscall.S must be before overrides.c, which must be last.
set(PRELOAD_FILES
  syscall_hook.S
  syscallbuf.c
  raw_syscall.S
  overrides.c
)
set(PRELOAD_SOURCE_FILES
  ${PRELOAD_FILES}
  preload_interface.h
  rrcalls.h
  syscallbuf.h
)
if (x86ish)
add_library(rrpreload)
foreach(file ${PRELOAD_FILES})
  target_sources(rrpreload PUBLIC "${CMAKE_SOURCE_DIR}/src/preload/${file}")
  set_source_files_properties("${CMAKE_SOURCE_DIR}/src/preload/${file}"
                              PROPERTIES COMPILE_FLAGS ${PRELOAD_COMPILE_FLAGS})
endforeach(file)
set_target_properties(rrpreload PROPERTIES LINK_FLAGS "-nostartfiles ${LINKER_FLAGS}")
set_target_properties(rrpreload PROPERTIES INSTALL_RPATH "\$ORIGIN")
endif()

set(AUDIT_FILES
  rtld-audit.c
  stap-note-iter.c
  ../preload/raw_syscall.S
)
set(AUDIT_SOURCE_FILES
  ${AUDIT_FILES}
  rtld-audit.h
  stap-note-iter.h
  ../preload/preload_interface.h
  ../preload/rrcalls.h
)
add_library(rraudit)
foreach(file ${AUDIT_FILES})
  target_sources(rraudit PUBLIC "${CMAKE_SOURCE_DIR}/src/audit/${file}")
  set_source_files_properties("${CMAKE_SOURCE_DIR}/src/audit/${file}"
                              PROPERTIES COMPILE_FLAGS ${PRELOAD_COMPILE_FLAGS})
endforeach(file)
set_target_properties(rraudit PROPERTIES LINK_FLAGS "-nostartfiles -ldl ${LINKER_FLAGS}")

# Ensure that CMake knows about our generated files.
#
# Alphabetical, please.
set(GENERATED_FILES
  AssemblyTemplates.generated
  CheckSyscallNumbers.generated
  SyscallEnumsX64.generated
  SyscallEnumsX86.generated
  SyscallEnumsGeneric.generated
  SyscallEnumsForTestsX64.generated
  SyscallEnumsForTestsX86.generated
  SyscallEnumsForTestsGeneric.generated
  SyscallHelperFunctions.generated
  SyscallnameArch.generated
  SyscallRecordCase.generated
)

foreach(generated_file ${GENERATED_FILES})
  set_source_files_properties(${generated_file}
                              PROPERTIES GENERATED true HEADER_FILE_ONLY true)
  add_custom_command(OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/${generated_file}"
                     COMMAND "${CMAKE_CURRENT_SOURCE_DIR}/src/generate_syscalls.py"
                             "${CMAKE_CURRENT_BINARY_DIR}/${generated_file}"
                     DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/src/generate_syscalls.py"
                             "${CMAKE_CURRENT_SOURCE_DIR}/src/syscalls.py"
                             "${CMAKE_CURRENT_SOURCE_DIR}/src/assembly_templates.py")
endforeach(generated_file)

add_custom_target(Generated DEPENDS ${GENERATED_FILES})

add_custom_command(OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/rr_trace.capnp.c++"
                          "${CMAKE_CURRENT_BINARY_DIR}/rr_trace.capnp.h"
                   COMMAND capnp compile
                           "--src-prefix=${CMAKE_CURRENT_SOURCE_DIR}/src"
                           "-oc++:${CMAKE_CURRENT_BINARY_DIR}"
                           "${CMAKE_CURRENT_SOURCE_DIR}/src/rr_trace.capnp"
                   DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/src/rr_trace.capnp")
set_source_files_properties("${CMAKE_CURRENT_BINARY_DIR}/rr_trace.capnp.c++"
                            PROPERTIES GENERATED true)
set_source_files_properties("${CMAKE_CURRENT_BINARY_DIR}/rr_trace.capnp.h"
                            PROPERTIES GENERATED true HEADER_FILE_ONLY true)

if (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "aarch64")
  set(BLAKE_ARCH_DIR third-party/blake2/neon)
else()
  set(BLAKE_ARCH_DIR third-party/blake2/sse)
endif()

set(RR_SOURCES
  src/AddressSpace.cc
  src/AutoRemoteSyscalls.cc
  src/BuildidCommand.cc
  src/Command.cc
  src/CompressedReader.cc
  src/CompressedWriter.cc
  src/CPUFeaturesCommand.cc
  src/CPUIDBugDetector.cc
  src/DiversionSession.cc
  src/DumpCommand.cc
  src/Dwarf.cc
  src/ElfReader.cc
  src/EmuFs.cc
  src/Event.cc
  src/ExtraRegisters.cc
  src/fast_forward.cc
  src/FdTable.cc
  src/FileMonitor.cc
  src/FileNameCommand.cc
  src/Flags.cc
  src/ftrace.cc
  src/GdbCommand.cc
  src/GdbCommandHandler.cc
  src/GdbConnection.cc
  src/GdbExpression.cc
  src/GdbInitCommand.cc
  src/GdbServer.cc
  src/HasTaskSet.cc
  src/HelpCommand.cc
  src/kernel_abi.cc
  src/kernel_metadata.cc
  src/log.cc
  src/LsCommand.cc
  src/MagicSaveDataMonitor.cc
  src/MmappedFileMonitor.cc
  src/MonitoredSharedMemory.cc
  src/Monkeypatcher.cc
  src/PackCommand.cc
  src/PerfCounters.cc
  src/ProcFdDirMonitor.cc
  src/ProcMemMonitor.cc
  src/ProcStatMonitor.cc
  src/PsCommand.cc
  src/RecordCommand.cc
  src/RecordSession.cc
  src/record_signal.cc
  src/record_syscall.cc
  src/RecordTask.cc
  src/Registers.cc
  src/remote_code_ptr.cc
  src/ReplayCommand.cc
  src/ReplaySession.cc
  src/replay_syscall.cc
  src/ReplayTask.cc
  src/ReplayTimeline.cc
  src/RerunCommand.cc
  src/ReturnAddressList.cc
  src/Scheduler.cc
  src/SeccompFilterRewriter.cc
  src/Session.cc
  src/SourcesCommand.cc
  src/StdioMonitor.cc
  src/SysCpuMonitor.cc
  src/Task.cc
  src/ThreadGroup.cc
  src/ThreadDb.cc
  src/TraceFrame.cc
  src/TraceInfoCommand.cc
  src/TraceStream.cc
  src/VirtualPerfCounterMonitor.cc
  src/util.cc
  src/WaitStatus.cc
  ${CMAKE_CURRENT_BINARY_DIR}/rr_trace.capnp.c++
  ${BLAKE_ARCH_DIR}/blake2b.c
)

if (x86ish)
  set(RR_SOURCES ${RR_SOURCES} src/test/x86/cpuid_loop.S)
endif()

set_source_files_properties(${RR_SOURCES}
                            PROPERTIES COMPILE_FLAGS ${RR_FLAGS})

function(post_build_executable target)
# grsecurity needs these. But if we add them ourselves, they may conflict
# with other flags added in other ways, and they all have to match :-(. So
# don't do this until a better solution presents itself
#  add_custom_command(TARGET ${target}
#                     POST_BUILD
#                     COMMAND setfattr ARGS -n user.pax.flags -v m $<TARGET_FILE:${target}>)
endfunction(post_build_executable)

if(UNIX)
  include(GNUInstallDirs)
else()
  set(CMAKE_INSTALL_LIBDIR "lib")
  set(CMAKE_INSTALL_BINDIR "bin")
  set(CMAKE_INSTALL_DATADIR "share")
  set(CMAKE_INSTALL_DOCDIR "${CMAKE_INSTALL_DATADIR}/doc")
  set(CMAKE_INSTALL_INCLUDEDIR "include")
endif()

add_executable(rr ${RR_SOURCES} src/main.cc)
set_target_properties(rr PROPERTIES ENABLE_EXPORTS true)
post_build_executable(rr)
set(RR_BIN rr)
add_dependencies(rr Generated)

option(strip "Strip debug info from rr binary")

set(RR_MAIN_LINKER_FLAGS ${LINKER_FLAGS})
if(strip)
  set(RR_MAIN_LINKER_FLAGS "-s ${RR_MAIN_LINKER_FLAGS}")
endif()

target_link_libraries(rr
  ${CMAKE_DL_LIBS}
  -lrt
  brotli
)

if(staticlibs)
  # Urgh ... this might not work for everyone, but there doesn't seem to be
  # a way to persuade pkg-confing/pkg_check_modules to produce the right flags
  target_link_libraries(rr -L/home/roc/lib -l:libcapnp.a -l:libkj.a)
  # Note that this works for both clang++ and g++
  set(RR_MAIN_LINKER_FLAGS "-static-libstdc++ ${RR_MAIN_LINKER_FLAGS}")
else()
  target_link_libraries(rr ${CAPNP_LDFLAGS})
endif()

set_target_properties(rr PROPERTIES LINK_FLAGS "${RR_MAIN_LINKER_FLAGS}")

if (x86ish)
target_link_libraries(rrpreload
  ${CMAKE_DL_LIBS}
)
endif()

add_executable(rr_exec_stub src/exec_stub.c)
post_build_executable(rr_exec_stub)
set_target_properties(rr_exec_stub
                      PROPERTIES LINK_FLAGS "-static -nostartfiles -nodefaultlibs ${LINKER_FLAGS}")
set_source_files_properties(src/exec_stub.c
                            COMPILE_FLAGS "-fno-stack-protector")

set(RR_GDB_RESOURCES
  32bit-avx.xml
  32bit-core.xml
  32bit-linux.xml
  32bit-sse.xml
  64bit-avx.xml
  64bit-core.xml
  64bit-linux.xml
  64bit-seg.xml
  64bit-sse.xml
  amd64-avx-linux.xml
  amd64-linux.xml
  i386-avx-linux.xml
  i386-linux.xml
  aarch64-core.xml
  aarch64-fpu.xml
  aarch64-pauth.xml
)
foreach(file ${RR_GDB_RESOURCES})
  configure_file("${CMAKE_CURRENT_SOURCE_DIR}/third-party/gdb/${file}"
                 "${CMAKE_CURRENT_BINARY_DIR}/share/rr/${file}"
                 COPYONLY)
  install(FILES third-party/gdb/${file}
          DESTINATION ${CMAKE_INSTALL_DATADIR}/rr)
endforeach(file)

foreach(file ${PRELOAD_SOURCE_FILES})
  configure_file("${CMAKE_CURRENT_SOURCE_DIR}/src/preload/${file}"
                 "${CMAKE_CURRENT_BINARY_DIR}/share/rr/src/preload/${file}"
                 COPYONLY)
  install(FILES src/preload/${file}
          DESTINATION ${CMAKE_INSTALL_DATADIR}/rr/src/preload)
endforeach(file)

foreach(file ${RR_PAGE_SOURCE_FILES})
  configure_file("${CMAKE_CURRENT_SOURCE_DIR}/src/preload/${file}"
                 "${CMAKE_CURRENT_BINARY_DIR}/share/rr/src/preload/${file}"
                 COPYONLY)
  install(FILES src/preload/${file}
          DESTINATION ${CMAKE_INSTALL_DATADIR}/rr/src/preload)
endforeach(file)

configure_file("${CMAKE_CURRENT_SOURCE_DIR}/scripts/rr-collect-symbols.py"
               "${CMAKE_CURRENT_BINARY_DIR}/bin/rr-collect-symbols.py"
               COPYONLY)

install(PROGRAMS scripts/signal-rr-recording.sh
                 scripts/rr-collect-symbols.py
  DESTINATION ${CMAKE_INSTALL_BINDIR})

install(PROGRAMS scripts/rr_completion
  DESTINATION ${CMAKE_INSTALL_DATADIR}/bash-completion/completions RENAME rr)

set(RR_INSTALL_LIBS rrpage rraudit rr_exec_stub)
if (x86ish)
  set(RR_INSTALL_LIBS rrpreload ${RR_INSTALL_LIBS})
endif()
install(TARGETS ${RR_BIN} ${RR_INSTALL_LIBS}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}/rr
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/rr)

# Build 32-bit librrpreload and librraudit on 64-bit builds.
# We copy the source files into '32' subdirectories in the output
# directory, so we can set different compile options on them.
# This sucks but I can't find a better way to get CMake to build
# the same source file in two different ways.
if(rr_32BIT AND rr_64BIT)
  add_library(rrpage_32)

  foreach(file ${RR_PAGE_SOURCE_FILES})
    configure_file("${CMAKE_CURRENT_SOURCE_DIR}/src/preload/${file}"
                   "${CMAKE_CURRENT_BINARY_DIR}/32/preload/${file}"
                   COPYONLY)
  endforeach(file)

  foreach(file ${RR_PAGE_FILES})
    target_sources(rrpage_32 PUBLIC "${CMAKE_CURRENT_BINARY_DIR}/32/preload/${file}")
    set_source_files_properties("${CMAKE_CURRENT_BINARY_DIR}/32/preload/${file}"
                                PROPERTIES COMPILE_FLAGS "-m32 ${PRELOAD_COMPILE_FLAGS}")
  endforeach(file)

  set_target_properties(rrpage_32 PROPERTIES NO_SONAME ON)
  set_target_properties(rrpage_32 PROPERTIES LINK_FLAGS "-m32 -Wl,-T -Wl,${CMAKE_SOURCE_DIR}/src/preload/rr_page.ld -Wl,--hash-style=both -nostartfiles -nostdlib -Wl,-soname,linux-vdso.so.1 ${LINKER_FLAGS}")
  set_target_properties(rrpage_32 PROPERTIES LINK_DEPENDS ${CMAKE_SOURCE_DIR}/src/preload/rr_page.ld)
  set_target_properties(rrpage_32 PROPERTIES LINKER_LANGUAGE C)

  add_custom_command(TARGET rrpage_32 POST_BUILD
                    COMMAND ${CMAKE_SOURCE_DIR}/src/preload/tweak_librrpage.py $<TARGET_FILE:rrpage_32>)


  add_library(rrpreload_32)

  foreach(file ${PRELOAD_SOURCE_FILES})
    configure_file("${CMAKE_CURRENT_SOURCE_DIR}/src/preload/${file}"
                   "${CMAKE_CURRENT_BINARY_DIR}/32/preload/${file}"
                   COPYONLY)
  endforeach(file)

  foreach(file ${PRELOAD_FILES})
    target_sources(rrpreload_32 PUBLIC "${CMAKE_CURRENT_BINARY_DIR}/32/preload/${file}")
    set_source_files_properties("${CMAKE_CURRENT_BINARY_DIR}/32/preload/${file}"
                                PROPERTIES COMPILE_FLAGS "-m32 ${PRELOAD_COMPILE_FLAGS}")
  endforeach(file)

  set_target_properties(rrpreload_32 PROPERTIES LINK_FLAGS "-m32 -nostartfiles ${LINKER_FLAGS}")
  set_target_properties(rrpreload_32 PROPERTIES INSTALL_RPATH "\$ORIGIN")
  target_link_libraries(rrpreload_32
    ${CMAKE_DL_LIBS}
  )

  add_library(rraudit_32)

  foreach(file ${AUDIT_SOURCE_FILES})
    configure_file("${CMAKE_CURRENT_SOURCE_DIR}/src/audit/${file}"
                   "${CMAKE_CURRENT_BINARY_DIR}/32/audit/${file}"
                   COPYONLY)
  endforeach(file)

  foreach(file ${AUDIT_FILES})
    target_sources(rraudit_32 PUBLIC "${CMAKE_CURRENT_BINARY_DIR}/32/audit/${file}")
    set_source_files_properties("${CMAKE_CURRENT_BINARY_DIR}/32/audit/${file}"
                                PROPERTIES COMPILE_FLAGS "-m32 ${PRELOAD_COMPILE_FLAGS}")
  endforeach(file)

  set_target_properties(rraudit_32 PROPERTIES LINK_FLAGS "-m32 -nostartfiles ${LINKER_FLAGS}")
  target_link_libraries(rraudit_32
    ${CMAKE_DL_LIBS}
  )

  foreach(file exec_stub.c)
    configure_file("${CMAKE_CURRENT_SOURCE_DIR}/src/${file}"
                   "${CMAKE_CURRENT_BINARY_DIR}/32/${file}"
                   COPYONLY)
    set_source_files_properties("${CMAKE_CURRENT_BINARY_DIR}/32/${file}"
                                PROPERTIES COMPILE_FLAGS "-m32 -fno-stack-protector")
  endforeach(file)

  add_executable(rr_exec_stub_32 32/exec_stub.c)
  post_build_executable(rr_exec_stub_32)
  set_target_properties(rr_exec_stub_32
                        PROPERTIES LINK_FLAGS "-static -nostartfiles -nodefaultlibs -m32 ${LINKER_FLAGS}")

  install(TARGETS rrpreload_32 rrpage_32 rraudit_32 rr_exec_stub_32
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}/rr
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/rr)
endif()

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
  _llseek
  abort
  accept
  acct
  adjtimex
  aio
  alarm
  alarm2
  alsa_ioctl
  arch_prctl
  async_segv_ignored
  at_threadexit
  bad_ip
  bad_syscall
  barrier
  big_buffers
  block
  block_open
  bpf
  brk
  brk2
  capget
  chew_cpu
  x86/chew_cpu_cpuid
  chmod
  chown
  clock
  clock_adjtime
  clock_nanosleep
  clock_time64
  clone
  clone_bad_stack
  clone_bad_tls
  clone_cleartid_coredump
  clone_fail
  clone_file_range
  clone_immediate_exit
  clone_newflags
  clone_parent
  clone_untraced
  clone_vfork_pidfd
  cloned_sigmask
  constructor
  copy_file_range
  x86/cpuid_same_state
  creat_address_not_truncated
  x86/cross_arch
  cwd_inaccessible
  daemon
  desched_blocking_poll
  detach_state
  detach_threads
  deterministic_sigsys
  dev_zero
  direct
  dup
  doublesegv
  epoll_create
  epoll_create1
  epoll_pwait_eintr_sigmask
  eventfd
  exec_flags
  exec_no_env
  exec_self
  exec_from_main_thread
  exec_from_other_thread
  exec_stopsig
  exit_with_syscallbuf_signal
  fadvise
  fanotify
  fatal_init_signal
  fatal_sigsegv_thread
  x86/fault_in_code_page
  fcntl_dupfd
  fcntl_misc
  fcntl_notify
  fcntl_owner_ex
  fcntl_rw_hints
  fcntl_seals
  fcntl_sig
  fd_cleanup
  fd_tracking_across_threads
  fds_clean
  flock
  flock_ofd
  flock2
  fork_brk
  fork_child_crash
  fork_many
  futex_exit_race
  futex_exit_race_sigsegv
  futex_pi
  futex_priorities
  futex_requeue
  gcrypt_rdrand
  getcpu
  getgroups
  getpwnam
  getrandom
  setitimer
  getsid
  gettimeofday
  grandchild_threads
  grandchild_threads_main_running
  grandchild_threads_thread_running
  grandchild_threads_parent_alive
  x86/hle
  inotify
  int3
  intr_futex_wait_restart
  intr_poll
  intr_ppoll
  intr_pselect
  intr_read_no_restart
  intr_read_restart
  intr_sleep
  intr_sleep_no_restart
  invalid_exec
  invalid_fcntl
  invalid_ioctl
  io
  io_uring
  ioctl
  ioctl_blk
  ioctl_fb
  ioctl_fs
  ioctl_pty
  ioctl_sg
  ioctl_tty
  ioctl_vt
  ioprio
  x86/ioperm
  x86/iopl
  join_threads
  joystick
  kcmp
  keyctl
  kill_newborn
  kill_ptracee
  large_hole
  large_write_deadlock
  legacy_ugid
  x86/lsl
  madvise
  madvise_free
  madvise_wipeonfork
  map_fixed
  map_shared_syscall
  membarrier
  memfd_create
  memfd_create_shared
  memfd_create_shared_huge
  mincore
  mknod
  mlock
  mmap_adjacent_to_rr_usage
  mmap_private
  mmap_private_grow_under_map
  mmap_ro
  mmap_self_maps_shared
  mmap_shared
  mmap_shared_dev_zero
  mmap_shared_grow
  mmap_shared_grow_under_map
  mmap_shared_multiple
  mmap_shared_subpage
  mmap_shared_write
  mmap_shared_write_fork
  mmap_short_file
  mmap_write_complex
  mmap_zero_size_fd
  x86/modify_ldt
  mount_ns_exec
  mount_ns_exec2
  mprotect
  mprotect_heterogenous
  mprotect_none
  mprotect_stack
  mq
  mremap
  mremap_after_coalesce
  mremap_grow
  mremap_grow_shared
  mremap_non_page_size
  mremap_overwrite
  mremap_private_grow_under_map
  mremap_shrink
  msg
  msg_trunc
  msync
  mtio
  multiple_pending_signals
  multiple_pending_signals_sequential
  munmap_segv
  munmap_discontinuous
  nanosleep
  netfilter
  netlink_mmap_disable
  no_mask_timeslice
  nscd
  numa
  x86/old_fork
  orphan_process
  packet_mmap_disable
  pause
  perf_event
  personality
  pid_ns_kill_child
  pid_ns_kill_child_threads
  pid_ns_kill_child_zombie
  pid_ns_kill_threads
  pid_ns_kill_threads_exit_wait
  pid_ns_reap
  pid_ns_segv
  pid_ns_shutdown
  pidfd
  x86/pkeys
  poll_sig_race
  ppoll
  prctl
  prctl_caps
  prctl_deathsig
  prctl_name
  prctl_short_name
  prctl_speculation_ctrl
  x86/prctl_tsc
  privileged_net_ioctl
  proc_fds
  proc_mem
  protect_rr_fds
  prw
  pthread_condvar_locking
  pthread_mutex_timedlock
  pthread_pi_mutex
  pthread_rwlocks
  x86/ptrace
  ptrace_attach_null_status
  ptrace_attach_running
  ptrace_attach_sleeping
  ptrace_attach_stopped
  ptrace_attach_thread_running
  ptrace_breakpoint
  ptrace_change_patched_syscall
  x86/ptrace_debug_regs
  ptrace_exec
  x86/ptrace_exec32
  ptrace_kill_grandtracee
  x86/ptrace_tls
  ptrace_seize
  ptrace_sigchld_blocked
  ptrace_signals
  ptrace_singlestep
  ptrace_syscall
  ptrace_syscall_clone_untraced
  x86/ptrace_sysemu
  ptrace_sysemu_syscall
  ptrace_trace_clone
  ptrace_trace_exit
  ptrace_traceme
  ptracer_death
  ptracer_death_multithread
  ptracer_death_multithread_peer
  # pivot_root ... disabled because it fails when run as root and does nothing otherwise
  quotactl
  x86/rdtsc
  read_nothing
  readdir
  read_large
  read_oversize
  readlink
  readlinkat
  readv
  record_replay_subject
  recvfrom
  redzone_integrity
  rename
  rlimit
  robust_futex
  rseq
  rusage
  samask
  save_data_fd
  sched_attr
  sched_setaffinity
  sched_setparam
  sched_yield
  sched_yield_to_lower_priority
  scm_rights
  scratch_read
  seccomp
  seccomp_cloning
  seccomp_clone_fail
  seccomp_desched
  seccomp_kill_exit
  seccomp_null
  seccomp_sigsys_args
  seccomp_sigsys_sigtrap
  seccomp_sigsys_syscallbuf
  seccomp_tsync
  seccomp_veto_exec
  self_shebang
  self_sigint
  sem
  send_block
  sendfile
  set_ptracer
  set_tid_address
  setgid
  setgroups
  setsid
  setuid
  shared_exec
  shared_monitor
  shared_offset
  shared_write
  shm
  shm_unmap
  sigaction_old
  sigaltstack
  sigchld_interrupt_signal
  sigcont
  sighandler_bad_rsp_sigsegv
  sighandler_fork
  sighandler_mask
  sigill
  signal_deferred
  signal_during_preload_init
  signal_frame
  signal_unstoppable
  signalfd
  sigprocmask
  sigprocmask_ensure_delivery
  sigprocmask_exec
  sigprocmask_evil
  sigprocmask_in_syscallbuf_sighandler
  sigprocmask_rr_sigs
  sigprocmask_syscallbuf
  sigqueueinfo
  x86/sigreturn
  sigreturn_reg
  sigreturnmask
  sigrt
  sigstop
  sigstop2
  sigsuspend
  sigtrap
  simple_threads_stress
  sioc
  small_holes
  sock_names_opts
  spinlock_priorities
  splice
  stack_growth_after_syscallbuf
  stack_growth_syscallbuf
  stack_growth_with_guard
  stack_invalid
  stack_overflow
  stack_overflow_altstack
  stack_overflow_with_guard
  statfs
  statx
  stdout_child
  stdout_cloexec
  stdout_dup
  stdout_redirect
  switch_read
  symlink
  sync
  sync_file_range
  syscall_bp
  syscall_in_writable_mem
  syscallbuf_signal_reset
  syscallbuf_signal_blocking
  syscallbuf_sigstop
  syscallbuf_timeslice
  syscallbuf_timeslice2
  sysconf
  sysctl
  sysemu_singlestep
  x86/sysfs
  sysinfo
  tgkill
  thread_yield
  timer
  timerfd
  times
  truncate_temp
  tun
  two_signals_with_mask
  ulimit_low
  uname
  unexpected_exit
  unexpected_exit_execve
  unexpected_exit_execve_twice
  unexpected_exit_pid_ns
  unjoined_thread
  unshare
  userfaultfd
  utimes
  vdso_parts
  vfork_flush
  vfork_shared
  video_capture
  vm_readv_writev
  vsyscall
  vsyscall_timeslice
  x86/x87env
  wait
  wait_sigstop
  write_race
  writev
  xattr
  zero_length_read
)

set(BASIC_CPP_TESTS
  std_random
  unwind_rr_page
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
  alternate_thread_diversion
  args
  async_kill_with_threads
  async_kill_with_threads_main_running
  async_kill_with_threads_thread_running
  async_segv
  async_signal_syscalls
  async_signal_syscalls2
  async_signal_syscalls_siginfo
  async_usr1
  blacklist
  block_clone_checkpoint
  block_clone_interrupted
  block_clone_syscallbuf_overflow
  block_intr_sigchld
  blocked_bad_ip
  blocked_sigill
  x86/blocked_sigsegv
  breakpoint
  breakpoint_conditions
  breakpoint_overlap
  call_function
  call_gettid
  # Disabled because it's very slow
  # check_session_leaks
  checkpoint_dying_threads
  checkpoint_mixed_mode
  checksum_sanity
  check_lost_interrupts
  clone_interruption
  # Disabled because it fails
  # clone_share_vm
  clone_vfork
  conditional_breakpoint_calls
  conditional_breakpoint_offload
  condvar_stress
  cont_race
  x86/cpuid_singlestep
  crash
  crash_in_function
  daemon_read
  dconf_mock
  dev_tty
  diversion_sigtrap
  diversion_syscall
  dlopen
  early_error
  elapsed_time
  exclusion_region
  exec_failed
  exec_many
  execve_loop
  exit_codes
  exit_group
  exit_race
  exit_status
  x86/explicit_checkpoints
  fd_limit
  fork_stress
  fork_syscalls
  function_calls
  x86/fxregs
  getcwd
  gdb_bogus_breakpoint
  goto_event
  hello
  hooks
  # Disabled because issue #1806 makes tests fail on Debian 8.5 at least
  # history
  ignored_async_usr1
  ignored_sigsegv
  ignore_nested
  immediate_restart
  x86/int3_ok
  interrupt
  intr_ptrace_decline
  invalid_interpreter
  invalid_jump
  jit_proc_mem
  link
  madvise_dontfork
  main_thread_exit
  mmap_fd_reuse_checkpoint
  mmap_replace_most_mappings
  mmap_shared_prot
  mmap_shared_write_exec_race
  mmap_tmpfs
  mmap_write
  mmap_write_private
  morestack_unwind
  mprotect_growsdown
  mprotect_syscallbuf_overflow
  mutex_pi_stress
  nested_detach_wait
  overflow_branch_counter
  patch_page_end
  x86/patch_40_80_f6_81
  priority
  ptrace_remote_unmap
  remove_latest_trace
  # Not called ps, because that interferes with using real 'ps' in tests
  rr_ps
  rr_ps_ns
  read_big_struct
  restart_abnormal_exit
  reverse_continue_breakpoint
  reverse_continue_multiprocess
  reverse_continue_process_signal
  reverse_many_breakpoints
  reverse_step_long
  reverse_step_threads
  reverse_step_threads_break
  search
  seccomp_blocks_rr
  seccomp_signals
  segfault
  shared_map
  shared_persistent_file
  signal_numbers
  sigprocmask_race
  sigprocmask_rr_sigs_nondefault
  simple
  x86/singlestep_pushf
  stack_growth
  step_thread
  strict_priorities
  x86/string_instructions
  x86/string_instructions_async_signals
  x86/string_instructions_async_signals_shared
  x86/string_instructions_multiwatch
  x86/string_instructions_replay
  x86/string_instructions_singlestep_fastforward
  x86/string_instructions_watch
  syscallbuf_fd_disabling
  syscallbuf_signal_blocking_read
  sysconf_onln
  target_fork
  target_process
  tcp_sockets
  term_nonmain
  term_rr
  term_trace_reset
  term_trace_syscall
  thread_exit_signal
  thread_open_race
  thread_stress
  threaded_syscall_spam
  threads
  tls
  ttyname
  unexpected_stack_growth
  user_ignore_sig
  vdso_clock_gettime_stack
  vdso_gettimeofday_stack
  vdso_time_stack
  vfork
  vfork_read_clone_stress
  vsyscall_reverse_next
  wait_for_all
  watchpoint
  watchpoint_at_sched
  watchpoint_before_signal
  watchpoint_no_progress
  watchpoint_size_change
  watchpoint_syscall
  watchpoint_unaligned
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
  x86/break_rdtsc
  break_sigreturn
  break_sync_signal
  break_thread
  break_time_slice
  breakpoint_consistent
  call_exit
  check_patched_pthread
  checkpoint_async_signal_syscalls_1000
  checkpoint_mmap_shared
  checkpoint_prctl_name
  checkpoint_simple
  checksum_sanity_noclone
  cont_signal
  x86/cpuid
  dead_thread_target
  desched_ticks
  deliver_async_signal_during_syscalls
  env_newline
  exec_deleted
  exec_stop
  execp
  explicit_checkpoint_clone
  file_name_newline
  final_sigkill
  first_instruction
  fork_exec_info_thr
  get_thread_list
  hardlink_mmapped_files
  hbreak
  mprotect_step
  nested_detach
  nested_detach_kill
  nested_release
  parent_no_break_child_bkpt
  parent_no_stop_child_crash
  post_exec_fpu_regs
  proc_maps
  read_bad_mem
  record_replay
  remove_watchpoint
  replay_overlarge_event_number
  replay_serve_files
  restart_invalid_checkpoint
  restart_unstable
  restart_diversion
  reverse_alarm
  reverse_continue_exec_subprocess
  reverse_continue_fork_subprocess
  reverse_continue_int3
  reverse_continue_start
  reverse_finish
  reverse_step_breakpoint
  reverse_step_signal
  reverse_step_threads2
  reverse_watchpoint
  reverse_watchpoint_syscall
  run_end
  run_in_function
  sanity
  seekticks
  shm_checkpoint
  siginfo
  x86/sigreturn_checksum
  signal_stop
  signal_checkpoint
  simple_script
  simple_script_debug
  simple_winch
  stack_overflow_debug
  step1
  x86/step_rdtsc
  step_signal
  x86/string_instructions_break
  x86/string_instructions_replay_quirk
  subprocess_exit_ends_session
  switch_processes
  syscallbuf_timeslice_250
  trace_version
  term_trace_cpu
  trace_events
  tty
  unmap_vdso
  unwind_on_signal
  vfork_exec
  vfork_break_parent
  vsyscall_singlestep
  watch_code
  watchpoint_cond
  when
)

if(BUILD_TESTS)
  # Part of the installable testsuite (test files).
  if(INSTALL_TESTSUITE)
    install(DIRECTORY ${CMAKE_SOURCE_DIR}/src/test/
            DESTINATION ${CMAKE_INSTALL_LIBDIR}/rr/testsuite/rr/src/test
            USE_SOURCE_PERMISSIONS)
  endif(INSTALL_TESTSUITE)

  # We use symlinks in the tests to access the build and source directories.
  # This is needed because we cannot change the paths used by the tests when
  # the testsuite is installed. We work around this by using symlinks during
  # the normal build, and then installing symlinks with the testsuite that
  # have the same name but, the new link targets.
  execute_process(COMMAND ${CMAKE_COMMAND} -E create_symlink ${CMAKE_SOURCE_DIR} source_dir)
  execute_process(COMMAND ${CMAKE_COMMAND} -E create_symlink ${PROJECT_BINARY_DIR} bin_dir)

  if(INSTALL_TESTSUITE)
    # Create the directory for the symlinks first and then create symlinks.
    install(CODE "execute_process(COMMAND ${CMAKE_COMMAND} -E make_directory
                  \$ENV{DESTDIR}\${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}/rr/testsuite/obj)
                  execute_process(COMMAND ${CMAKE_COMMAND} -E create_symlink
                  \${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}/rr/testsuite/rr
                  \$ENV{DESTDIR}\${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}/rr/testsuite/obj/source_dir)
                  execute_process(COMMAND ${CMAKE_COMMAND} -E create_symlink
                  \${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}/rr/testsuite/obj
                  \$ENV{DESTDIR}\${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}/rr/testsuite/obj/bin_dir)")
  endif(INSTALL_TESTSUITE)

  add_test(check_environment
      bash source_dir/src/test/check_environment_test.run)
  set_tests_properties(check_environment
      PROPERTIES FAIL_REGULAR_EXPRESSION "rr needs /proc/sys/kernel/perf_event_paranoid <= 1")

  foreach(test ${BASIC_TESTS} ${TESTS_WITH_PROGRAM})
    if (NOT x86ish AND ${test} MATCHES "^x86/.*")
      continue()
    endif()
    get_filename_component(testname ${test} NAME)

    add_executable(${testname} src/test/${test}.c)
    target_include_directories(${testname} PRIVATE src/preload)
    post_build_executable(${testname})
    set_source_files_properties(src/test/${test}.c
                                PROPERTIES COMPILE_FLAGS ${RR_TEST_FLAGS})
    add_dependencies(${testname} Generated)
    target_link_libraries(${testname} -lrt -ldl)
    # Part of the installable testsuite (test programs).
    if(INSTALL_TESTSUITE)
      install(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/bin/${testname}
              DESTINATION ${CMAKE_INSTALL_LIBDIR}/rr/testsuite/obj/bin)
    endif(INSTALL_TESTSUITE)
  endforeach(test)

  # Test disabled because it requires libuvc to be built and installed, and a
  # working USB camera
  # add_executable(usb src/test/usb.c)
  # post_build_executable(usb)
  # add_dependencies(usb Generated)
  # target_link_libraries(usb -lrt -L/usr/local/lib -luvc -lusb-1.0)

  foreach(test ${BASIC_CPP_TESTS})
    add_executable(${test} src/test/${test}.cc)
    post_build_executable(${test})
    set_source_files_properties(src/test/${test}.cc
                                PROPERTIES COMPILE_FLAGS ${RR_TEST_FLAGS})
    add_dependencies(${test} Generated)
    target_link_libraries(${test} -lrt)
    # Part of the installable testsuite (test programs).
    if(INSTALL_TESTSUITE)
      install(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/bin/${test}
              DESTINATION ${CMAKE_INSTALL_LIBDIR}/rr/testsuite/obj/bin)
    endif(INSTALL_TESTSUITE)
  endforeach(test)

  add_library(test_lib
    src/test/test_lib.c
    )
  add_dependencies(test_lib Generated)
  set_source_files_properties(src/test/test_lib.c
                              PROPERTIES COMPILE_FLAGS ${RR_TEST_FLAGS})
  target_link_libraries(constructor -lrt test_lib)

  # cpuid test needs to link with cpuid_loop.S
  if (x86ish)
    add_executable(cpuid src/test/x86/cpuid.c src/test/x86/cpuid_loop.S)
    post_build_executable(cpuid)
    set_source_files_properties(src/test/x86/cpuid.c
                                PROPERTIES COMPILE_FLAGS ${RR_TEST_FLAGS})
    add_dependencies(cpuid Generated)
    target_link_libraries(cpuid -lrt)
  endif()

  # Check if we're running on KNL. If so, we allot more time to tests, due to
  # reduced single-core performance.
  exec_program(cat ARGS "/proc/cpuinfo" OUTPUT_VARIABLE CPUINFO)
  string(REGEX MATCH "^.*(Xeon Phi).*$" CPU_MODEL_PHI ${CPUINFO})
  if(NOT "${CPU_MODEL_PHI}" STREQUAL "")
    set(TEST_MONITOR_DEFAULT_TIMEOUT 480)
  else()
    set(TEST_MONITOR_DEFAULT_TIMEOUT 120)
  endif()

  # The real timeouts are handled by test-monitor
  set(CTEST_TEST_TIMEOUT 1000)

  function(configure_test test)
    set_tests_properties(${test} PROPERTIES FAIL_REGULAR_EXPRESSION "FAILED")
  endfunction(configure_test)

  if(INSTALL_TESTSUITE)
    install(TARGETS test_lib
            LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}/rr)
    install(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/bin/test-monitor
            DESTINATION ${CMAKE_INSTALL_LIBDIR}/rr/testsuite/obj/bin)
    if (x86ish)
      install(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/bin/cpuid
              DESTINATION ${CMAKE_INSTALL_LIBDIR}/rr/testsuite/obj/bin)
    endif(x86ish)
    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/CTestTestfile.cmake
            DESTINATION ${CMAKE_INSTALL_LIBDIR}/rr/testsuite/obj)
  endif(INSTALL_TESTSUITE)

  foreach(test ${BASIC_TESTS} ${BASIC_CPP_TESTS} ${OTHER_TESTS})
    if (NOT x86ish AND ${test} MATCHES "^x86/.*")
      continue()
    endif()
    get_filename_component(testname ${test} NAME)
    add_test(${test}
      bash source_dir/src/test/basic_test.run ${testname} "" bin_dir ${TEST_MONITOR_DEFAULT_TIMEOUT})
    configure_test(${test})
    add_test(${test}-no-syscallbuf
      bash source_dir/src/test/basic_test.run ${testname} -n bin_dir ${TEST_MONITOR_DEFAULT_TIMEOUT})
    configure_test(${test}-no-syscallbuf)
  endforeach(test)

  foreach(test ${TESTS_WITH_PROGRAM} ${TESTS_WITHOUT_PROGRAM})
    if (NOT x86ish AND ${test} MATCHES "^x86/.*")
      continue()
    endif()
    get_filename_component(testname ${test} NAME)
    add_test(${test}
      bash source_dir/src/test/${test}.run ${testname} "" bin_dir ${TEST_MONITOR_DEFAULT_TIMEOUT})
    configure_test(${test})
    add_test(${test}-no-syscallbuf
      bash source_dir/src/test/${test}.run ${testname} -n bin_dir ${TEST_MONITOR_DEFAULT_TIMEOUT})
    configure_test(${test}-no-syscallbuf)
  endforeach(test)

  # Run 32-bit tests on 64-bit builds.
  # We copy the test files into '32' subdirectories in the output
  # directory, so we can set different compile options on them.
  # This sucks but I can't find a better way to get CMake to build
  # the same source file in two different ways.
  if(rr_32BIT AND rr_64BIT)
    foreach(header util.h nsutils.h ptrace_util.h util_internal.h)
      configure_file("${CMAKE_CURRENT_SOURCE_DIR}/src/test/${header}"
                    "${CMAKE_CURRENT_BINARY_DIR}/32/${header}"
                    COPYONLY)
    endforeach(header)

    foreach(test ${BASIC_TESTS} ${TESTS_WITH_PROGRAM} x86/cpuid test_lib)
      configure_file("${CMAKE_CURRENT_SOURCE_DIR}/src/test/${test}.c"
                     "${CMAKE_CURRENT_BINARY_DIR}/32/${test}.c"
                     COPYONLY)
      set_source_files_properties("${CMAKE_CURRENT_BINARY_DIR}/32/${test}.c"
                                  PROPERTIES COMPILE_FLAGS "-m32 ${RR_TEST_FLAGS}")
    endforeach(test)

    foreach(test ${BASIC_CPP_TESTS})
      configure_file("${CMAKE_CURRENT_SOURCE_DIR}/src/test/${test}.cc"
                     "${CMAKE_CURRENT_BINARY_DIR}/32/${test}.cc"
                     COPYONLY)
      set_source_files_properties("${CMAKE_CURRENT_BINARY_DIR}/32/${test}.cc"
                                  PROPERTIES COMPILE_FLAGS "-m32 ${RR_TEST_FLAGS}")
    endforeach(test)

    foreach(file x86/cpuid_loop.S x86/util.h)
      configure_file("${CMAKE_CURRENT_SOURCE_DIR}/src/test/${file}"
                     "${CMAKE_CURRENT_BINARY_DIR}/32/${file}"
                     COPYONLY)
      set_source_files_properties("${CMAKE_CURRENT_BINARY_DIR}/32/${file}"
                                  PROPERTIES COMPILE_FLAGS "-m32 ${RR_TEST_FLAGS}")
    endforeach(file)

    foreach(test ${BASIC_TESTS} ${BASIC_CPP_TESTS} ${TESTS_WITH_PROGRAM})
      get_filename_component(testname ${test} NAME)
      if(EXISTS "${CMAKE_CURRENT_BINARY_DIR}/32/${test}.c")
        add_executable(${testname}_32 "${CMAKE_CURRENT_BINARY_DIR}/32/${test}.c")
      else()
        add_executable(${testname}_32 "${CMAKE_CURRENT_BINARY_DIR}/32/${test}.cc")
      endif()
      target_include_directories(${testname}_32 PRIVATE src/preload)
      post_build_executable(${testname}_32)
      add_dependencies(${testname}_32 Generated)
      set_target_properties(${testname}_32 PROPERTIES LINK_FLAGS "-m32 ${RR_TEST_FLAGS} ${LINKER_FLAGS}")
      target_link_libraries(${testname}_32 -lrt -ldl)
      # Part of the installable testsuite (test programs).
      if (INSTALL_TESTSUITE)
        install(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/bin/${testname}_32
                DESTINATION ${CMAKE_INSTALL_LIBDIR}/rr/testsuite/obj/bin)
      endif (INSTALL_TESTSUITE)
    endforeach(test)

    add_library(test_lib_32
      "${CMAKE_CURRENT_BINARY_DIR}/32/test_lib.c"
    )
    add_dependencies(test_lib_32 Generated)
    set_target_properties(test_lib_32 PROPERTIES LINK_FLAGS "-m32 ${LINKER_FLAGS}")

    target_link_libraries(constructor_32 -lrt test_lib_32)

    # cpuid test needs to link with cpuid_loop.S
    add_executable(cpuid_32 32/x86/cpuid.c 32/x86/cpuid_loop.S)
    post_build_executable(cpuid_32)
    add_dependencies(cpuid_32 Generated)
    set_target_properties(cpuid_32 PROPERTIES LINK_FLAGS "-m32 ${LINKER_FLAGS}")
    target_link_libraries(cpuid_32 -lrt)

    if(INSTALL_TESTSUITE)
      install(TARGETS test_lib_32
              LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}/rr)
      install(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/bin/cpuid_32
              DESTINATION ${CMAKE_INSTALL_LIBDIR}/rr/testsuite/obj/bin)
    endif(INSTALL_TESTSUITE)

    foreach(test ${BASIC_TESTS} ${BASIC_CPP_TESTS} ${OTHER_TESTS})
      get_filename_component(testname ${test} NAME)
      add_test(${test}-32
        bash source_dir/src/test/basic_test.run ${testname}_32 "" bin_dir ${TEST_MONITOR_DEFAULT_TIMEOUT})
      configure_test(${test}-32)
      add_test(${test}-32-no-syscallbuf
        bash source_dir/src/test/basic_test.run ${testname}_32 -n bin_dir ${TEST_MONITOR_DEFAULT_TIMEOUT})
      configure_test(${test}-32-no-syscallbuf)
    endforeach(test)

    foreach(test ${TESTS_WITH_PROGRAM} ${TESTS_WITHOUT_PROGRAM})
      get_filename_component(testname ${test} NAME)
      add_test(${test}-32
        bash source_dir/src/test/${test}.run ${testname}_32 "" bin_dir ${TEST_MONITOR_DEFAULT_TIMEOUT})
      configure_test(${test}-32)
      add_test(${test}-32-no-syscallbuf
        bash source_dir/src/test/${test}.run ${testname}_32 -n bin_dir ${TEST_MONITOR_DEFAULT_TIMEOUT})
      configure_test(${test}-32-no-syscallbuf)
    endforeach(test)
  endif()

  set(CHAOS_TESTS
    core_count
    futex_wakeup
    getaffinity_core_count
    pipe_wakeup
    mmap_adjacent
    mmap_bits
    starvation_multithreaded
    starvation_singlethreaded
  )

  foreach(test ${CHAOS_TESTS})
    add_executable(${test} src/chaos-test/${test}.c)
    post_build_executable(${test})
    target_link_libraries(${test} -lrt)
  endforeach(test)

  add_executable(test-monitor src/test-monitor/test-monitor.cc)
endif()

add_executable(ftrace_helper src/ftrace/ftrace_helper.c)

include(ProcessorCount)
ProcessorCount(N)
if(NOT N EQUAL 0)
  set(JFLAG -j${N})
endif()

add_custom_target(check COMMAND ${CMAKE_CTEST_COMMAND} --verbose ${JFLAG})
# Run only syscallbuf-enabled and native-bitness tests
add_custom_target(fastcheck COMMAND ${CMAKE_CTEST_COMMAND} --verbose --exclude-regex '[-]' ${JFLAG})

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
# Don't strip binaries. It's important/useful for librrpreload at least to
# have debug symbols. For package releases, pass -Dstrip=TRUE to strip symbols
# from the rr binary at build time.
set(CPACK_STRIP_FILES FALSE)

set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_SOURCE_DIR}/LICENSE")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY
  "Lightweight tool for recording and replaying execution of applications (trees of processes and threads)")
set(CPACK_PACKAGE_DESCRIPTION_FILE "${CMAKE_SOURCE_DIR}/README.md")
set(CPACK_PACKAGE_VENDOR "rr-debugger")

set(CPACK_DEBIAN_PACKAGE_MAINTAINER "rr-debugger")
set(CPACK_DEBIAN_PACKAGE_SECTION "devel")
if(${CMAKE_SYSTEM_PROCESSOR} STREQUAL "x86_64")
  set(CPACK_DEBIAN_PACKAGE_ARCHITECTURE "amd64")
elseif(${CMAKE_SYSTEM_PROCESSOR} MATCHES "i.86")
  set(CPACK_DEBIAN_PACKAGE_ARCHITECTURE "i386")
elseif(${CMAKE_SYSTEM_PROCESSOR} MATCHES "arm.*")
  set(CPACK_DEBIAN_PACKAGE_ARCHITECTURE "arm")
endif()

# XXX Cmake 2.8.7 doesn't know how to avoid specifying /usr,
# /usr/bin, etc, as files to be installed, but distros are finicky
# about their specification.  We want to manually filter those paths
# out of our install list but 2.8.7 also isn't capable of that.
set(CPACK_RPM_USER_BINARY_SPECFILE "${CMAKE_SOURCE_DIR}/rr.spec")
set(CPACK_RPM_PACKAGE_RELEASE 1)
set(CPACK_RPM_PACKAGE_GROUP "Development/Debuggers")
set(CPACK_RPM_PACKAGE_LICENSE "MIT and BSD")
# Prevent binaries from being stripped
set(CPACK_RPM_SPEC_INSTALL_POST "/bin/true")

include (CPack)

##--------------------------------------------------
## Misc

add_custom_target(setup-travis COMMAND src/script/setup_travis.sh)
