from util import *

bp = set_breakpoint('breakpoint')

def test():
    for type in ['uint16_t', 'uint32_t', 'uint64_t']:
        send_gdb('c')
        expect_gdb(f'Breakpoint {bp}')
        wp = set_watchpoint(f'-l *({type} *)wp_addr')
        send_gdb('c')
        expect_gdb(f'watchpoint {wp}')
        send_gdb(f'delete {wp}')

test()
test()
ok()
