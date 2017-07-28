from util import *

def observe_normal_parent_exit():
    expect_rr('EXIT-SUCCESS')
    expect_gdb(r'Inferior 1 \(process \d+\) exited normally')

send_gdb('c')
observe_normal_parent_exit()

restart_replay()
observe_normal_parent_exit()

ok()
