#include <immintrin.h>

#if defined(__AVX512F__)

static int broadcast_to_three_zmm(void) {
    asm volatile (
        "vpbroadcastb %0, %%zmm0 \n\t"
        :
        : "r"(0x1a)
        : "zmm0"
    );
#if !defined(__ILP32__)
    asm volatile (
        "vpbroadcastb %0, %%zmm16 \n\t"
        :
        : "r"(0x5b)
        : "zmm16"
    );
    asm volatile (
        "vpbroadcastb %0, %%zmm30 \n\t"
        :
        : "r"(0xff)
        : "zmm30"
    );
#else // 32-bit only has 0-8 vector registers 
    asm volatile (
        "vpbroadcastb %0, %%zmm4 \n\t"
        :
        : "r"(0x5b)
        : "zmm4"
    );
    asm volatile (
        "vpbroadcastb %0, %%zmm7 \n\t"
        :
        : "r"(0xff)
        : "zmm7"
    );
#endif
    return 0;
}

#else
#error "AVX512 is required"
#endif

int
main(void)
{
#ifdef __AVX512F__
  int a = broadcast_to_three_zmm();
  return a;
#endif
  return 1;
}
