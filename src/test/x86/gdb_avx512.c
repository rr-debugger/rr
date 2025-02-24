static int set_registers(void) {

    __attribute__((aligned(64))) unsigned char increasing[64];
    __attribute__((aligned(64))) unsigned char decreasing[64];

    for (int i = 0; i < 64; i++) {
        increasing[i] = i + 1;
        decreasing[i] = 0xFF - i;
    }

    // __m512i zmm1;  // Declare the ZMM register variable
    // Inline assembly to fill the registers
    __asm__ volatile (
        "vmovdqu64 %0, %%zmm0  \n\t"  // Load increasing bytes into zmm0
        :: "m"(increasing)
        :
    );
    __asm__ volatile (
        "vmovdqu64 %0, %%zmm1  \n\t"  // Load increasing bytes into zmm0
        :: "m"(decreasing)
        :
    );
    return 0;
}

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
        :
    );
    asm volatile (
        "vpbroadcastb %0, %%zmm30 \n\t"
        :
        : "r"(0xff)
        :
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

int main(void)
{
  int a = set_registers();
  int b = broadcast_to_three_zmm();
  return a + b;
}
