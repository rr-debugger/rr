import argparse
import os
import struct
import sys

parser = argparse.ArgumentParser()
group = parser.add_mutually_exclusive_group()
group.add_argument('--reset', action='store_true')
group.add_argument('--check', action='store_true')
args = parser.parse_args()

# MSRC001_1020: Load-Store Configuration
MSR = 0xc0011020
# Disable SpecLockMap
BIT = 1 << 54

if not os.path.exists('/dev/cpu/0/msr'):
    ret = os.system('modprobe msr')
    if ret:
        sys.exit(ret)

def read_msr(cpu):
    msr = os.open('/dev/cpu/{}/msr'.format(cpu), os.O_RDONLY)
    os.lseek(msr, MSR, os.SEEK_SET)
    (val,) = struct.unpack('<q', os.read(msr, 8))
    os.close(msr)
    return val

cpus = [cpu for cpu in os.listdir('/dev/cpu') if cpu.isdigit()]

if not args.check:
    for cpu in cpus:
        val = read_msr(cpu)
        if args.reset:
            if val & BIT == 0:
                continue
            val &= ~BIT
        else:
            if val & BIT:
                continue
            val |= BIT
        msr = os.open('/dev/cpu/{}/msr'.format(cpu), os.O_WRONLY)
        os.lseek(msr, MSR, os.SEEK_SET)
        os.write(msr, struct.pack('<q', val))
        os.close(msr)

if not args.reset:
    import ctypes
    lib = ctypes.CDLL(None)
    prctl = lib.prctl
    prctl.restype = ctypes.c_int
    prctl.argtypes = (ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong)
    # Try to enable SSB mitigation. On Zen and Zen+, this is known to make the kernel overwrite
    # the MSR and reset the bit we just set.
    PR_SET_SPECULATION_CTRL = 53
    PR_SPEC_STORE_BYPASS = 0
    PR_SPEC_DISABLE = 1 << 2
    mitigated = (prctl(PR_SET_SPECULATION_CTRL, PR_SPEC_STORE_BYPASS, PR_SPEC_DISABLE, 0, 0) == 0)
    if not mitigated:
        print('Failed to enable SSB mitigation')

msrs = [read_msr(cpu) & BIT for cpu in cpus]

if all(msr for msr in msrs):
    if mitigated or args.check:
        print('Zen workaround in place')
    else:
        print('Zen workaround maybe in place.')
elif args.reset or args.check:
    if all(not msr for msr in msrs):
        print('Zen workaround disabled')
    elif args.reset:
        print('Zen workaround somehow not entirely disabled?')
    else:
        print('Zen workaround not entirely enabled?')
else:
    print('Zen workaround does not stick. Please see https://github.com/mozilla/rr/wiki/Zen')
