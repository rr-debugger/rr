from rrutil import *

send_gdb('b breakpoint')
expect_gdb('Breakpoint 1')

send_gdb('c')
expect_gdb('Breakpoint 1, breakpoint')

# See fxregs.c for the list of constants that are loaded into the
# $st0-$st7 and $xmm0-$xmm7 registers.
for i in xrange(8):
    send_gdb('p $st%d'% (i))
    expect_gdb(' = %d'% (i + 1))

for i in xrange(8):
    send_gdb('p $xmm%d.v4_float[0]'% (i))
    expect_gdb(' = %d'% (i + 10))

ok()
