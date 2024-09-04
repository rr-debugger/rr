from util import *

breakpoint = breakpoint_at_function('main')
cont()
expect_breakpoint_stop(breakpoint)

watchpoint_at_address("&buffer[0]", 1)
watchpoint_at_address("&buffer[8]", 1)
watchpoint_at_address("&buffer[16]", 1)
wp4 = watchpoint_at_address("&buffer[24]", 1)
watchpoint_at_address_fail("&buffer[32]", 1)

delete_watchpoint(wp4)
watchpoint_at_address("&buffer[24]", 1)

breakpoint_puts = breakpoint_at_function('atomic_puts')
cont()
expect_breakpoint_stop(breakpoint_puts)

ok()

