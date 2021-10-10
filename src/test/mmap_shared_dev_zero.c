#include "util.h"

#include <assert.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>

int main(void) {
  size_t page_size = sysconf(_SC_PAGE_SIZE);
  int fd = open("/dev/zero", O_RDWR);
  void* p1 = mmap(0, page_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  assert(p1 != MAP_FAILED);
  void* p2 = mmap(0, page_size, PROT_READ, MAP_SHARED, fd, 0);
  assert(p2 != MAP_FAILED);
  assert(p1 != p2);

  memset(p1, 0xdd, page_size);
  // Verify that these mappings are not connected.
  assert(*(long*)p2 == 0);
  atomic_printf("EXIT-SUCCESS");
  return 0;
}
