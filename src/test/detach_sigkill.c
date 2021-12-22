/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util_internal.h"

static int parent_to_child[2];
static int child_to_parent[2];

int main(__attribute__((unused)) int argc,
         __attribute__((unused)) char **argv) {
    int status;
    char ch;
    pid_t pid;

    test_assert(0 == pipe(parent_to_child));
    test_assert(0 == pipe(child_to_parent));

    if (0 == (pid = fork())) {
        if (running_under_rr()) {
            rr_detach_teleport();
        }
        // Signal that we are ready
        test_assert(1 == read(parent_to_child[0], &ch, 1) && ch == 'y');
        test_assert(1 == write(child_to_parent[1], "x", 1));
        pause();
        test_assert(0);
    }

    test_assert(1 == write(parent_to_child[1], "y", 1));
    test_assert(1 == read(child_to_parent[0], &ch, 1) && ch == 'x');

    kill(pid, SIGKILL);

    test_assert(pid == waitpid(pid, &status, 0));
    test_assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
    atomic_puts("EXIT-SUCCESS");
    return 0;
}
