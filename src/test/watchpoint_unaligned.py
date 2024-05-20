from util import *

bp = set_breakpoint('breakpoint')

def test():
    for type in ['uint16_t', 'uint32_t', 'uint64_t']:
        send_gdb('c')
        expect_gdb(f'Breakpoint {bp}')
        # Get the value of `wp_addr` from the parent frame.
        # On Ubuntu 20 LTS, gdb stops before the `breakpoint` prelude so
        # gets the wrong value of `wp_addr`.
        send_gdb('up')
        expect_gdb('test')
        wp = set_watchpoint(f'-l *({type} *)wp_addr')
        send_gdb('c')
        expect_gdb(f'watchpoint {wp}')
        send_gdb(f'delete {wp}')

test()
test()
test()
ok()
