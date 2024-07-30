from util import *
import sys
import os

test = os.getenv("TESTNAME")

send_gdb('break 39')
expect_gdb('Breakpoint 1')
send_gdb('c')
expect_gdb('Breakpoint 1')

send_gdb("print/x $xmm0.uint128")
expect_gdb(r"0x1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a")

send_gdb("print/x $ymm0.v2_int128")
expect_gdb(r"0x1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a,\s+0x1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a")

send_gdb("print/x $zmm0.v4_int128")
expect_gdb(r"0x1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a,\s+0x1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a,\s+0x1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a,\s+0x1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a")

regs_per_mode = []

if test[-3:] == "_32":
  regs_per_mode = [4, 7]
else:
  regs_per_mode = [16, 30]

send_gdb(f"print/x $xmm{regs_per_mode[0]}.uint128")
expect_gdb(r"0x5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b")

send_gdb(f"print/x $ymm{regs_per_mode[0]}.v2_int128")
expect_gdb(r"0x5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b,\s+0x5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b")

send_gdb(f"print/x $zmm{regs_per_mode[0]}.v4_int128")
expect_gdb(r"0x5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b,\s+0x5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b,\s+0x5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b,\s+0x5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b")

send_gdb(f"print/x $xmm{regs_per_mode[1]}.uint128")
expect_gdb(r"0xffffffffffffffffffffffffffffffff")

send_gdb(f"print/x $ymm{regs_per_mode[1]}.v2_int128")
expect_gdb(r"0xffffffffffffffffffffffffffffffff,\s+0xffffffffffffffffffffffffffffffff")

send_gdb(f"print/x $zmm{regs_per_mode[1]}.v4_int128")
expect_gdb(r"0xffffffffffffffffffffffffffffffff,\s+0xffffffffffffffffffffffffffffffff,\s+0xffffffffffffffffffffffffffffffff,\s+0xffffffffffffffffffffffffffffffff")

send_gdb('c')
ok()
