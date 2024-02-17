from util import *

breakpoint = breakpoint_at_function('breakpoint')

def test():
    for size in [2, 4, 8]:
        send_gdb('c')
        expect_breakpoint_stop(breakpoint)
        # Get the value of `wp_addr` from the parent frame.
        # On Ubuntu 20 LTS, gdb stops before the `breakpoint` prelude so
        # gets the wrong value of `wp_addr`.
        send_gdb('up')
        expect_gdb('test')
        wp = watchpoint_at_address('wp_addr', size)
        send_gdb('c')
        expect_watchpoint_stop(wp)
        send_gdb(f'delete {wp}')

test()
test()
test()
ok()
