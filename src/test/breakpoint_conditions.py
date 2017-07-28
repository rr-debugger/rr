from util import *

def test_cond(c):
    send_gdb('cond 1 %s'%c)
    # check that the condition is evaluated correctly by checking that
    # we don't break on the negation of the condition
    send_gdb('cond 2 !(%s)'%c)
    send_gdb('c')
    expect_gdb('Breakpoint 1')

send_gdb('b breakpointA')
expect_gdb('Breakpoint 1')
send_gdb('b breakpointB')
expect_gdb('Breakpoint 2')

test_cond('v1==1')
test_cond('v1!=2')
test_cond('v4==4')
test_cond('v1+v2==3')
test_cond('v2-1==v1')
test_cond('v3-v2==1')
test_cond('v4>>2==v1')
test_cond('v1<<2==v4')
test_cond('(unsigned char)u64max==255')
test_cond('v2*v2==4')
test_cond('v4/v2==2')
test_cond('v4/vm2==-2')
test_cond('v3%v2==1')
test_cond('v3%vm2==1')
test_cond('!v1==v0')
test_cond('v1|v2==3')
test_cond('v3&v2==2')
test_cond('v3^v2==1')
test_cond('~v0==(int)u64max')
test_cond('v0?v1:v2==2')
test_cond('*p==(int)u64max')
test_cond('*(unsigned char*)p==255')
test_cond('*(short int*)p==-1')
test_cond('*(long long*)p==(long long)u64max')

ok()
