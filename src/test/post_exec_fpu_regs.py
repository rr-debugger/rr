from util import *
import re

arch = get_exe_arch()

if arch == 'aarch64':
    send_gdb('p $v0.d.u')
    expect_gdb('{0, 0}')
elif arch == 'i386' or arch == 'i386:x86-64':
    send_gdb('p $xmm0')
    expect_gdb('v4_float = {0, 0, 0, 0}')

ok()
