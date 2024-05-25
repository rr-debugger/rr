from util import *

breakpoint = breakpoint_at_function('breakpoint')

def test():
    for size in [2, 4, 8]:
        cont()
        expect_breakpoint_stop(breakpoint)
        # Get the value of `wp_addr` from the parent frame.
        # On Ubuntu 20 LTS, gdb stops before the `breakpoint` prelude so
        # gets the wrong value of `wp_addr`.
        up()
        expect_debugger('test')
        wp = watchpoint_at_address('wp_addr', size)
        cont()
        expect_watchpoint_stop(wp)
        delete_watchpoint(wp)

test()
test()
test()
ok()
