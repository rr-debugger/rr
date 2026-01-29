#include "util.h"
#include <time.h>
/*
#include <assert.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/memfd.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
*/
#define memfd_create(...) syscall(__NR_memfd_create, __VA_ARGS__)

typedef void (*simple_func_t)(void);

#ifdef __x86_64__
static const unsigned char x86_ret_instruction = 0xC3; // ret
static const unsigned long long func_size = 1;
#elif defined(__aarch64__)
static const unsigned int arm64_ret_instruction = 0xD65F03C0; // ret
static const unsigned long long func_size = 4;
#elif defined(__i386__)
#else
#error "Unsupported architecture"
#endif

/*
https://github.com/dotnet/runtime/blob/23aeecc9f91a9ae0a211702dbd849c90cdd81d36/src/coreclr/minipal/Unix/doublemapping.cpp#L85
#ifdef TARGET_64BIT
static const off_t MaxDoubleMappedSize = 2048ULL*1024*1024*1024;
#else
static const off_t MaxDoubleMappedSize = UINT_MAX;
#endif

*/
// To prevent bugs that could result in writing a 2TB file, a 10GB limit is used
// instead.
#define _1GB (1024 * 1024 * 1024ULL)
unsigned long long MaxDoubleMappedSize = 10 * _1GB;

int create_double_mapping(void **writable_addr, void **executable_addr,
                          unsigned long long size, int *fd_ptr)
{
  *writable_addr = MAP_FAILED;
  *executable_addr = MAP_FAILED;
  *fd_ptr = -1;
  int fd = memfd_create("double_mapper_test", MFD_CLOEXEC);
  do
  {
    if (fd == -1)
    {
      atomic_puts("memfd_create failed");
      break;
    }
    if (ftruncate(fd, MaxDoubleMappedSize) == -1)
    {
      atomic_puts("ftruncate failed");
      break;
    }
    *writable_addr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (*writable_addr == MAP_FAILED)
    {
      atomic_puts("mmap for writable mapping failed");
      break;
    }
    *executable_addr = mmap(NULL, size, PROT_READ | PROT_EXEC, MAP_SHARED, fd, 0);
    if (*executable_addr == MAP_FAILED)
    {
      atomic_puts("mmap for executable mapping failed");
      munmap(*writable_addr, size);
      break;
    }
    *fd_ptr = fd;
    return 0;
  } while (0);
  if(fd!=-1){
    close(fd);
  }
  return -1;
}

void free_double_mapping(void *writable_addr, void *executable_addr,
                         unsigned long long size)
{
  if (writable_addr != MAP_FAILED && writable_addr != NULL)
  {
    munmap(writable_addr, size);
  }
  if (executable_addr != MAP_FAILED && executable_addr != NULL)
  {
    munmap(executable_addr, size);
  }
}

void test_double_mapping(void)
{
  void *writable_addr = MAP_FAILED;
  void *executable_addr = MAP_FAILED;
  unsigned long long page_size = getpagesize();
  int memfd = -1;
  if (create_double_mapping(&writable_addr, &executable_addr, page_size,
                            &memfd) != 0)
  {
    return;
  }
  atomic_puts("Writing and Executing function to writable page...\n");
#ifdef __x86_64__
  memcpy(writable_addr, &x86_ret_instruction, func_size);
#elif defined(__aarch64__)
  memcpy(writable_addr, &arm64_ret_instruction, func_size);
#endif
  simple_func_t func = (simple_func_t)executable_addr;
  func();
  free_double_mapping(writable_addr, executable_addr, page_size);
  if (memfd != -1)
  {
    close(memfd);
  }
}

int main(void)
{
#if defined(__i386__)
  atomic_puts("Skipping test on 32 bit");
#else
  struct timespec start, end;
  long elapsed_seconds = 0;
  test_assert(-1 != clock_gettime(CLOCK_MONOTONIC, &start));
  test_double_mapping();
  test_assert(-1 != clock_gettime(CLOCK_MONOTONIC, &end));
  elapsed_seconds = end.tv_sec - start.tv_sec;
  //10GB/sec;
  long limited_sec = 2;
  atomic_printf("elapsed_seconds %ld :  limited_sec %ld \n", elapsed_seconds,
         limited_sec);
  /*check timeout*/
  test_assert(elapsed_seconds <= limited_sec);
#endif
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
