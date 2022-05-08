#include "util.h"

static unsigned count = 0;

void sig_handler(int sigNum) {
    (void)sigNum;
    ++count;
}

int main(void) {
    atomic_puts("XIT-START");
    test_assert(signal(SIGURG, sig_handler) != SIG_ERR);

    for (int i = 0; i < 10 * 1000; ++i) {
        raise(SIGURG);
    }

    atomic_puts("XIT-END");

    return 0;
}