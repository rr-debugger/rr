#include <unistd.h>

int main(void) {
  for (int i = 0; i < 500000; ++i) {
    getsid(0);
  }
  return 0;
}
