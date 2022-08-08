from util import *

send_gdb('break main')
expect_gdb('Breakpoint 1')
send_gdb('c')
expect_gdb('Breakpoint 1')

# This was supposed to check the unwinding in the bail path of the vdso,
# but we now unwind the syscallbuf before performing the bail syscall,
# so just check the stack at the main syscall_hook entry.
send_gdb('break syscall_hook')
expect_gdb('Breakpoint 2')
send_gdb('c')
expect_gdb('Breakpoint 2')

send_gdb('where')
expect_gdb(' main ')

ok()
