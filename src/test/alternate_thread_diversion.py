from util import *

bp = breakpoint_at_function('break_here')
cont()
expect_breakpoint_stop(bp)

expect_threads(num_threads=2, selected_thread=2)

select_thread(1)
scheduler_locking_on()
expect_expression('get_value()', 1)
scheduler_locking_off()
cont()
expect_signal_stop('SIGKILL')

ok()
