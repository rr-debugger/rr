#include "util.h"

static int string_cmp_equal(char* s, char* t, uintptr_t size) {
  int b;
  __asm__("repe cmpsb\n\t;"
          "sete %%al\n\t;"
          "movzx %%al,%0;": "=r"(b) : "S"(t), "D"(s), "c"(size) : "al");
  return b;
}

int main(void) {
  char* STRING1 = "almost_the_same1";
  char* STRING2 = "almost_the_same2";
  int x = string_cmp_equal(STRING1, STRING2, 17);
  return x;
}
