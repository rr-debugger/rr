#include "util.h"

// This simply execs the commands passed to it on
// the command line without passing through the
// environment. The runner uses this to test
// --nested=ignore in the absence of RR_UNDER_RR
// environment variable.
int main(int argc, char *argv[]) {
    if (argc > 1 && strcmp(argv[1], "--inner") == 0) {
        atomic_puts("EXIT-SUCCESS");
        return 0;
    }
    char *newenv[] = { NULL };
    return execve(argv[1], &argv[1], newenv);
}
