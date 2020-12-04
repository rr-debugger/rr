/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util_internal.h"

char path1[PATH_MAX];
char path2[PATH_MAX];

int main(int argc __attribute__((unused)), char **argv __attribute__((unused))) {
    pid_t pid = fork();
    if (pid == 0) {
        readlink("/proc/self/exe", path1, sizeof(path1));

        // Check that rlimits survive
        struct rlimit lim1, lim2;
        test_assert(0 == getrlimit(RLIMIT_STACK, &lim1));
        if (lim1.rlim_cur == RLIM_INFINITY) {
            lim1.rlim_cur = 2 * 1024 * 1024; // 2 MiB
        }
        lim1.rlim_cur = 2 * lim1.rlim_cur;
        if (lim1.rlim_max != RLIM_INFINITY && lim1.rlim_cur > lim1.rlim_max) {
            lim1.rlim_cur = lim1.rlim_max;
        }
        test_assert(0 == setrlimit(RLIMIT_STACK, &lim1));

        if (running_under_rr()) {
            rr_detach_teleport();
        }

        test_assert(0 == getrlimit(RLIMIT_STACK, &lim2));
        test_assert(0 == memcmp(&lim1, &lim2, sizeof(struct rlimit)));

        readlink("/proc/self/exe", path2, sizeof(path2));
        test_assert(0 == strcmp(path1, path2));
        return 0;
    }

    int status;
    wait(&status);
    test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    atomic_puts("EXIT-SUCCESS");
    return 0;
}
