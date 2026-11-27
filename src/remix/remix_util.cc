/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <algorithm>

#include "dr_api.h"

#include "engine.h"
#include "remix_util.h"

#include "Translation.h"
#include "remix.h"

REMIX_TARGET_BEGIN

#define ARCH_GET_CPUID 0x1011
#define ARCH_SET_CPUID 0x1012

using namespace std;

extern "C" {

uint32_t remix_log_modules;
RemixErrorDetails remix_error_details;

void remix_abort(const char* format, ...) {
  va_list ap;
  va_start(ap, format);
  char buf[0x10000];
  int ret = vsnprintf(buf, sizeof(buf), format, ap);
  va_end(ap);
  if (ret >= (int)sizeof(buf)) {
    ret = sizeof(buf);
    buf[sizeof(buf) - 1] = '\n';
  } else {
    buf[ret] = '\n';
    ++ret;
  }
  write(STDERR_FILENO, buf, ret);
  abort();
}

static char remix_prefix[40];
static int remix_prefix_len;

void remix_update_uid() {
  snprintf(remix_prefix, sizeof(remix_prefix), "[remix %d] ",
           remix_uid.rec_pid);
  remix_prefix_len = strlen(remix_prefix);
}

void remix_log(uint32_t module, const char* format, ...) {
  remix_assert(xmm_regs_saved());

  if (!(remix_log_modules & module)) {
    return;
  }

  if (!remix_prefix[0]) {
    remix_update_uid();
  }

  va_list ap;
  va_start(ap, format);
  char buf[0x10000];
  memcpy(buf, remix_prefix, remix_prefix_len);
  char* bufptr = buf + remix_prefix_len;
  size_t buflen = sizeof(buf) - remix_prefix_len;
  int ret = vsnprintf(bufptr, buflen, format, ap);
  va_end(ap);
  if (ret >= (int)buflen) {
    ret = buflen;
    bufptr[buflen - 1] = '\n';
  } else {
    bufptr[ret] = '\n';
    ++ret;
  }
  write(STDERR_FILENO, buf, ret + remix_prefix_len);
}

CPUIDData cpuid(uint32_t code, uint32_t subrequest) {
  CPUIDData result;

  int cpuid_faulting = syscall(SYS_arch_prctl, ARCH_GET_CPUID);
  if (cpuid_faulting == 0) {
    syscall(SYS_arch_prctl, ARCH_SET_CPUID, 1);
  }

  asm volatile("cpuid"
               : "=a"(result.eax), "=b"(result.ebx), "=c"(result.ecx),
                 "=d"(result.edx)
               : "a"(code), "c"(subrequest));

  if (cpuid_faulting == 0) {
    syscall(SYS_arch_prctl, ARCH_SET_CPUID, 0);
  }

  return result;
}

}

void memcpy_from_app(uint8_t* dest, uint8_t* app_src, size_t size) {
  // This could be optimized to coalesce mprotect operations
  while (size > 0) {
    uint8_t* app_src_page = floor_page_size(app_src);
    size_t len = min<size_t>(size, PAGE_SIZE - (app_src - app_src_page));
    int prot = Translation::get_hw_prot((app_pc)app_src_page);
    if (!(prot & PROT_READ)) {
      int ret = mprotect(app_src_page, PAGE_SIZE, prot | PROT_READ);
      remix_assert(ret == 0);
    }
    memcpy(dest, app_src, len);
    if (!(prot & PROT_READ)) {
      int ret = mprotect(app_src_page, PAGE_SIZE, prot);
      remix_assert(ret == 0);
    }
    dest += len;
    app_src += len;
    size -= len;
  }
}

void memcpy_to_app(uint8_t* app_dest, uint8_t* src, size_t size) {
  // This could be optimized to coalesce mprotect operations
  while (size > 0) {
    uint8_t* app_dest_page = floor_page_size(app_dest);
    size_t len = min<size_t>(size, PAGE_SIZE - (app_dest - app_dest_page));
    int prot = Translation::get_hw_prot((app_pc)app_dest_page);
    if (!(prot & PROT_WRITE)) {
      int ret = mprotect(app_dest_page, PAGE_SIZE, prot | PROT_WRITE);
      remix_assert(ret == 0);
    }
    memcpy(app_dest, src, len);
    if (!(prot & PROT_WRITE)) {
      int ret = mprotect(app_dest_page, PAGE_SIZE, prot);
      remix_assert(ret == 0);
    }
    app_dest += len;
    src += len;
    size -= len;
  }
}

// These regions can't overlap
static void swap_bytes(uint8_t* p1, uint8_t* p2, size_t size) {
  char buf[1024];
  while (size > 0) {
    size_t len = min<size_t>(1024, size);
    memcpy(buf, p1, len);
    memcpy(p1, p2, len);
    memcpy(p2, buf, len);
    p1 += len;
    p2 += len;
    size -= len;
  }
}

void swap_app_bytes(uint8_t* app, uint8_t* p, size_t size) {
  // This could be optimized to coalesce mprotect operations
  while (size > 0) {
    uint8_t* app_page = floor_page_size(app);
    size_t len = min<size_t>(size, PAGE_SIZE - (app - app_page));
    int prot = Translation::get_hw_prot((app_pc)app_page);
    if ((prot & (PROT_READ | PROT_WRITE)) != (PROT_READ | PROT_WRITE)) {
      int ret = mprotect(app_page, PAGE_SIZE, prot | PROT_READ | PROT_WRITE);
      remix_assert(ret == 0);
    }
    swap_bytes(app, p, len);
    if ((prot & (PROT_READ | PROT_WRITE)) != (PROT_READ | PROT_WRITE)) {
      int ret = mprotect(app_page, PAGE_SIZE, prot);
      remix_assert(ret == 0);
    }
    app += len;
    p += len;
    size -= len;
  }
}

REMIX_TARGET_END
