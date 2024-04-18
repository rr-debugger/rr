#!/usr/bin/env python3

import argparse
import os
import struct
import sys

import array
from os.path import join
from fcntl import ioctl
from enum import Enum

parser = argparse.ArgumentParser()
group = parser.add_mutually_exclusive_group()
group.add_argument('--reset', action='store_true')
group.add_argument('--check', action='store_true')
args = parser.parse_args()

# MSRC001_1020: Load-Store Configuration
MSR = 0xc0011020
# Disable SpecLockMap
BIT = 1 << 54


EFIVARS_PATH   = '/sys/firmware/efi/efivars/'
SecureBoot = Enum("SecureBoot", "enabled disabled checkfailed")
def is_secure_boot_enabled():
    if not os.path.isdir(EFIVARS_PATH):
        return SecureBoot.checkfailed

    files = [f for f in os.listdir(EFIVARS_PATH) if f.startswith("SecureBoot-")]
    var_path = join(EFIVARS_PATH, files[0])
    attr = []
    data = []
    try:
        if os.path.exists(var_path):
            with open(var_path, 'rb') as fd:
                buffer = fd.read()

                attr = buffer[:4]
                data = buffer[4:]
        if int(data[0]) == 1:
            return SecureBoot.enabled
        else:
            return SecureBoot.disabled
    except:
        return SecureBoot.checkfailed


if not os.path.exists('/dev/cpu/0/msr'):
    ret = os.system('modprobe msr')
    if ret:
        sys.exit(ret)

def read_msr(cpu):
    try:
        msr = os.open('/dev/cpu/{}/msr'.format(cpu), os.O_RDONLY)
    except PermissionError as e:
        sys.stderr.write(str(e) + '\n')
        print("Permission denied opening MSR for reading.")
        print("Try running as root / with sudo.")
        sys.exit(1)
    try:
        os.lseek(msr, MSR, os.SEEK_SET)
        (val,) = struct.unpack('<q', os.read(msr, 8))
        return val
    except PermissionError as e:
        sys.stderr.write(str(e) + '\n')
        print("Permission denied on reading from MSR.")
        sys.exit(1)
    except OSError as e:
        sys.stderr.write(str(e) + '\n')
        print("General error on reading from MSR.")
        sys.exit(1)
    finally:
        os.close(msr)

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
        try:
            msr = os.open('/dev/cpu/{}/msr'.format(cpu), os.O_WRONLY)
        except PermissionError:
            sys.stderr.write(str(e) + '\n')
            print("Permission denied opening MSR for writing.")
            print("Try running as root / with sudo.")
            sys.exit(1)

        try:
            os.lseek(msr, MSR, os.SEEK_SET)
            os.write(msr, struct.pack('<q', val))
        except PermissionError as e:
            check = is_secure_boot_enabled() 
            sys.stderr.write(str(e) + '\n')
            print("Permission denied writing to MSR.")
            if check == SecureBoot.enabled:
                print("Secure Boot is enabled, which causes this error. Try disabling Secure Boot.")
            elif check == SecureBoot.disabled:
                print("Secure Boot is disabled so that's not the problem.")
            print("You may want to use another approach, please see https://github.com/rr-debugger/rr/wiki/Zen.")
            sys.exit(1)
        except OSError as e:
            sys.stderr.write(str(e) + '\n')
            print("General error on writing to MSR.")
            sys.exit(1)
        finally:
            os.close(msr)

ssb_status = 'unknown'
if not args.reset:
    import ctypes
    lib = ctypes.CDLL(None)
    prctl = lib.prctl
    prctl.restype = ctypes.c_int
    prctl.argtypes = (ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong)
    PR_GET_SPECULATION_CTRL = 52
    PR_SET_SPECULATION_CTRL = 53
    PR_SPEC_STORE_BYPASS = 0
    PR_SPEC_PRCTL = 1 << 0
    PR_SPEC_DISABLE = 1 << 2
    # When the kernel does per-process SSB mitigation via prctl or seccomp, it touches the same
    # MSR that we changed, but does so based on a value of the MSR it got at boot time, so it
    # effectively will reset the bit we just set if it wasn't already set at boot time.
    # This doesn't happen when the SSB mitigation is either entirely on or off.
    # This is specific to Zen and Zen+, because Zen 2 doesn't require the kernel to change the MSR.
    # Check whether the kernel does per-process SSB mitigation, and if it does, enable it for this
    # process.
    ssb_mode = prctl(PR_GET_SPECULATION_CTRL, PR_SPEC_STORE_BYPASS, 0, 0, 0)
    if ssb_mode >= 0 and ssb_mode & PR_SPEC_PRCTL:
        mitigated = (prctl(PR_SET_SPECULATION_CTRL, PR_SPEC_STORE_BYPASS, PR_SPEC_DISABLE, 0, 0) == 0)
        if not mitigated:
            print('Failed to enable SSB mitigation')
        else:
            ssb_status = 'mitigated'
    else:
        ssb_status = 'immutable'


msrs = [read_msr(cpu) & BIT for cpu in cpus]

if all(msr for msr in msrs):
    if ssb_status in ('mitigated', 'immutable') or args.check:
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
    print('Zen workaround does not stick. Please see https://github.com/rr-debugger/rr/wiki/Zen')
