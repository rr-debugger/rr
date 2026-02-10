#include "util.h"
#include <time.h>
#define memfd_create(...) syscall(__NR_memfd_create, __VA_ARGS__)
/*
https://github.com/dotnet/runtime/blob/23aeecc9f91a9ae0a211702dbd849c90cdd81d36/src/coreclr/minipal/Unix/doublemapping.cpp#L85
#ifdef TARGET_64BIT
static const off_t MaxDoubleMappedSize = 2048ULL*1024*1024*1024;
#else
static const off_t MaxDoubleMappedSize = UINT_MAX;
#endif
To prevent bugs that could result in writing a 2TB file, a 20GB limit is used instead.
*/
#define _1GB (1024 * 1024 * 1024ULL)
unsigned long long MaxDoubleMappedSize = 20 * _1GB;
#define PAGE_SIZE_4K 4096
int test_ftruncate_huge_mapping(void)
{
  int ret=-1;
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
    void* executable_addr = mmap(NULL, PAGE_SIZE_4K, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, 0);
    if (executable_addr == MAP_FAILED)
    {
      atomic_puts("mmap for executable mapping failed");
      break;
    }
    munmap(executable_addr, PAGE_SIZE_4K);
    ret = 0;
  } while (0);
  if(fd!=-1){
    close(fd);
  }
  return ret;
}

int main(void)
{
#if defined(__i386__)
  atomic_puts("Skipping test on 32 bit");
#else
  struct timespec start, end;
  test_assert(-1 != clock_gettime(CLOCK_MONOTONIC, &start));
  test_ftruncate_huge_mapping();
  test_assert(-1 != clock_gettime(CLOCK_MONOTONIC, &end));
  //check timeout
  test_assert((end.tv_sec - start.tv_sec) <= 2);
#endif
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
