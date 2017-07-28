from util import *

restart_replay()
# A single EXIT-SUCCESS is expected since the child process to which we have
# attached only prints one, and it exits before the parent prints its
# EXIT-SUCCESS.
expect_rr('EXIT-SUCCESS')

ok()
