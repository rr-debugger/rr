/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util_internal.h"

static int parent_to_child[2];
static int child_to_parent[2];

int main(__attribute__((unused)) int argc,
         __attribute__((unused)) char **argv) {
    int status;
    char ch;
    pid_t pid;
    siginfo_t sig;

    test_assert(0 == pipe(parent_to_child));
    test_assert(0 == pipe(child_to_parent));

    if (0 == (pid = fork())) {
        if (running_under_rr()) {
            rr_detach_teleport();
        }
        // Signal that we are ready
        test_assert(1 == read(parent_to_child[0], &ch, 1) && ch == 'y');
        exit(24);
    }

    test_assert(1 == write(parent_to_child[1], "y", 1));

    // Give the child a chance to finish exiting
    test_assert(0 == waitid(P_PID, pid, &sig, WNOWAIT | WEXITED));
    test_assert(sig.si_pid == pid && sig.si_code == CLD_EXITED && sig.si_status == 24);

    // Now kill the detach proxy before reaping the child
    kill(pid, SIGKILL);

    // Let rr listen for the SIGKILL event
    usleep(100);

    test_assert(pid == waitpid(pid, &status, 0));
    test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 24);
    atomic_puts("EXIT-SUCCESS");
    return 0;
}
