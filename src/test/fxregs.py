from util import *
import re

send_gdb('b breakpoint')
expect_gdb('Breakpoint 1')

send_gdb('c')
expect_gdb('Breakpoint 1, breakpoint')

# See fxregs.c for the list of constants that are loaded into the
# $st*, $xmm* and $ymm* registers.
for i in xrange(8):
    send_gdb('p $st%d'%(i))
    expect_gdb(' = %d'%(i + 1))

for i in xrange(8):
    send_gdb('p $xmm%d.v4_float[0]'%(i))
    expect_gdb(' = %d'%(i + 10))

send_gdb('show architecture')
have_64 = 0 == expect_list([re.compile('i386:x86-64\)'), re.compile('i386\)')])

if have_64:
    for i in xrange(8,16):
        send_gdb('p $xmm%d.v4_float[0]'%(i))
        expect_gdb(' = %d'%(i + 10))

send_gdb('p AVX_enabled')
have_AVX = 0 == expect_list([re.compile(' = 1'), re.compile(' = 0')])

if have_AVX:
    for i in xrange(8):
        send_gdb('p $ymm%d.v8_float[0]'%(i))
        expect_gdb(' = %d'%(i + 10))
        send_gdb('p $ymm%d.v8_float[4]'%(i))
        expect_gdb(' = %d'%((i + 1)%8 + 10))
    if have_64:
        for i in xrange(8,16):
            send_gdb('p $ymm%d.v8_float[0]'%(i))
            expect_gdb(' = %d'%(i + 10))
            send_gdb('p $ymm%d.v8_float[4]'%(i))
            expect_gdb(' = %d'%((i - 8 + 1)%8 + 18))

ok()
