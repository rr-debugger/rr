from util import *

send_gdb('break breakpoint')
expect_gdb('Breakpoint 1')
send_gdb('c')
expect_gdb('Breakpoint 1')

send_gdb('find buf,+1,(char)0')
expect_gdb('<buf>')
expect_gdb('1 pattern found')

send_gdb('find buf,+1000,(char)99')
expect_gdb('Pattern not found')

send_gdb('find buf,+1000,(char)2')
expect_gdb('<buf')
expect_gdb('<buf')
expect_gdb('2 patterns found')

send_gdb('find buf,+14,(int)0')
expect_gdb('<buf')
expect_gdb('<buf')
expect_gdb('2 patterns found')

send_gdb('find buf,+1000,(char)1,(char)2')
expect_gdb('<buf')
expect_gdb('1 pattern found')

send_gdb('find p + (p_end - p)/2, +1, (char)0')
expect_gdb('1 pattern found')

send_gdb('find p,p_end,(char)1')
expect_gdb('2 patterns found')

send_gdb('find p, p + (p_end - p)/2,(char)0,(char)0,(char)1')
expect_gdb('Pattern not found')

# Test search string crossing page boundaries
send_gdb('find p, p_end,(char)0,(char)0,(char)1')
expect_gdb('1 pattern found')

# Search the whole address space
send_gdb('find 0,-10L,0xabcdef01')
expect_gdb('Pattern not found')

send_gdb('find 0,-10L,(char)0,(char)1,(char)2,(char)2,(char)3,(char)0xff,(char)0xfa,(char)0xde,(char)0xbc')
# One pattern in 'buf', and two in 'p'
expect_gdb('<buf>')
expect_gdb('3 patterns found')

send_gdb('up');
send_gdb('find 0,-10L,&argc')
expect_gdb('<argc_ptr>')
send_gdb('down');

ok()
