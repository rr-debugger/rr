#include <stdlib.h>
#include <sys/prctl.h>

int main(void) {
  return prctl(PR_SET_TSC, PR_TSC_ENABLE) == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
