#!/usr/bin/python3

import argparse
import glob
import json
import os
import re
import subprocess
import sys
import time

# These are where we build the release binaries. They should be as old as possible
# while still supported. Update these when the distro release is no longer supported.
dist_packaging = {
    ('ubuntu20-lts', 'x86_64'): 'TGZ;DEB',
    ('ubuntu22-lts', 'arm64'): 'TGZ;DEB',
    ('centos8', 'x86_64'): 'RPM',
    ('centos9', 'arm64'): 'RPM',
}

os.chdir(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

parser = argparse.ArgumentParser()
parser.add_argument('version')
parser.add_argument('keypair_pem_file')
args = parser.parse_args()

version_re = re.compile(r'(\d+)\.(\d+)\.(\d+)')
m = version_re.match(args.version)
if not m:
    raise ValueError('version must have three numeric components, got %s' % args.version)
major = int(m.group(1))
minor = int(m.group(2))
patch = int(m.group(3))
version = '%d.%d.%d' % (major, minor, patch)

dist_dir = '/tmp/rr-dist'
log_dir = '/tmp/rr-release-logs'

def check_call(args):
    print('Running %s' % args)
    subprocess.check_call(args)

def update_cmake(name, num):
    check_call(['sed', '-i',
        's/rr_VERSION_%s [0-9][0-9]*/rr_VERSION_%s %d/g' % (name, name, num),
        'CMakeLists.txt'])

def prepare_branch():
    output = subprocess.check_output(['git', 'status',
        '--untracked-files=no', '--porcelain'], stderr=subprocess.STDOUT)
    if output:
        print('Uncommitted changes in git workspace, aborting', file=sys.stderr)
        sys.exit(2)
    check_call(['git', 'checkout', '-B', 'release', 'master'])
    update_cmake('MAJOR', major)
    update_cmake('MINOR', minor)
    update_cmake('PATCH', patch)
    check_call(['git', 'commit', '-a', '-m', 'Bump version to %s' % version])
    check_call(['git', 'tag', '-f', version])
    check_call(['git', 'push', '-f', '--set-upstream', 'origin', 'release'])
    check_call(['git', 'checkout', 'master'])

def prepare_dirs():
    check_call(['rm', '-rf', dist_dir, log_dir])
    check_call(['mkdir', dist_dir, log_dir])

def output_file_name(distro_name, arch):
    return os.path.join(log_dir, '%s.%s' % (distro_name, arch))

def has_line_starting(output_file, prefix):
    with open(output_file, 'r') as f:
        for line in f:
            if line.startswith(prefix):
                return True
    return False

def start_vm(cmd, output_file):
    with open(output_file, 'w') as f:
        process = subprocess.Popen(cmd, stderr=subprocess.STDOUT, stdout=f)
    while True:
        time.sleep(1)
        if process.poll() is not None:
            if has_line_starting(output_file, 'botocore.exceptions.ClientError: An error occurred (VcpuLimitExceeded) '):
                return None
            return process
        if has_line_starting(output_file, 'Started VM '):
            return process

COLOR_SUCCESS = '\033[92m'
COLOR_FAILURE = '\033[91m'
COLOR_NORMAL = '\033[0m'

def run_tests():
    distro_files = glob.glob('release-process/distro-configs/*.json')
    pending = []
    for distro_file in sorted(distro_files):
        distro_name = os.path.basename(distro_file).rsplit('.', 1)[0]
        with open(distro_file, 'r') as f:
            distro_config = json.load(f)
        archs = distro_config['archs'] if 'archs' in distro_config else ['x86_64']
        for arch in sorted(archs):
            cmd = ['release-process/test-system.py', '--keep-vm-on-error',
                '--git-revision', 'release',
                distro_file, arch, args.keypair_pem_file]
            generators = dist_packaging.get((distro_name, arch))
            if generators is not None:
                cmd += ['--dist-files-dir', dist_dir, '--cpack-generators', generators]
            pending.append((distro_name, arch, cmd))
    running = []
    fail_count = 0
    while pending or running:
        while pending:
            distro_name, arch, cmd = pending[0]
            output_file = output_file_name(distro_name, arch)
            process = start_vm(cmd, output_file)
            if process:
                pending.pop(0)
                running.append((distro_name, arch, process))
                print('Started %s %s' % (distro_name, arch))
            else:
                break
        # If no exits are seen after 60 seconds, try to launch a new VM anyway.
        for i in range(60):
            ready_index = None
            for running_index, (distro_name, arch, process) in enumerate(running):
                if process.poll() is not None:
                    ready_index = running_index
                    break
            if ready_index is not None:
                distro_name, arch, process = running.pop(ready_index)
                output_file = output_file_name(distro_name, arch)
                vm_kept = has_line_starting(output_file, 'VM kept; ')
                if process.returncode:
                    print('%sTests failed%s: see %s%s' %
                        (COLOR_FAILURE, ' (VM kept)' if vm_kept else '', output_file, COLOR_NORMAL), file=sys.stderr)
                    fail_count += 1
                else:
                    print('%sTests succeeded for %s %s%s' % (COLOR_SUCCESS, distro_name, arch, COLOR_NORMAL))
                break
            time.sleep(1)
    print('%d failures total' % fail_count)
    if fail_count:
        sys.exit(1)
    else:
        print('Dist files left in %s' % dist_dir)

prepare_branch()
prepare_dirs()
run_tests()
