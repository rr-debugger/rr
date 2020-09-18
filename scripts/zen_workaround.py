import argparse
import os
import struct
import sys

parser = argparse.ArgumentParser()
parser.add_argument('--reset', action='store_true')
args = parser.parse_args()

# MSRC001_1020: Load-Store Configuration
MSR = 0xc0011020
# Disable SpecLockMap
BIT = 1 << 54

if not os.path.exists('/dev/cpu'):
    ret = os.system('modprobe msr')
    if ret:
        sys.exit(ret)

for cpu in os.listdir('/dev/cpu'):
    msr = os.open('/dev/cpu/{}/msr'.format(cpu), os.O_RDONLY)
    os.lseek(msr, MSR, os.SEEK_SET)
    (val,) = struct.unpack('<q', os.read(msr, 8))
    os.close(msr)
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
