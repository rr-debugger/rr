#!/usr/bin/python3

import argparse
import boto3
from datetime import datetime
import json
import pathlib
import subprocess
import sys
import time

parser = argparse.ArgumentParser()
parser.add_argument('distro_config_json')
parser.add_argument('architecture')
parser.add_argument('keypair_pem_file')
parser.add_argument('--cpack-generators', default='TGZ')
parser.add_argument('--git-revision', default='master')
parser.add_argument('--timeout', default=1200) # 20 minutes
parser.add_argument('--machine-type')
parser.add_argument('--keep-vm', action='store_true')
parser.add_argument('--keep-vm-on-error', action='store_true')
parser.add_argument('--dist-files-dir')
args = parser.parse_args()

class Ec2Vm:
    def __init__(self, machine_type, architecture, distro_config, keypair_pem_file):
        """Start an EC2 VM using the latest available AMI.
           If this completes without throwing an exception, then terminate()
           should be called eventually (unless you want to keep the VM running)."""
        self.distro_name = distro_config['name']
        self.user = distro_config['user']
        self.keypair_pem_file = keypair_pem_file
        self.ssh_ready = False
        self.ec2 = boto3.resource('ec2')
        self.ec2_client = boto3.client('ec2')

        response = self.ec2_client.describe_images(Owners=[distro_config['ami_owner']], Filters=[
            {'Name': 'architecture', 'Values': [architecture]},
            {'Name': 'name', 'Values': [distro_config['ami_name_pattern']]}
        ], MaxResults=1000)
        images = response['Images']
        if len(images) >= 1000:
            raise Exception('Too many AMIs match filter')
        if len(images) == 0:
            raise Exception('No AMIs match filter')
        latest_image = sorted(map(lambda image: (
            datetime.strptime(image['CreationDate'], '%Y-%m-%dT%H:%M:%S.%f%z'),
            image
        ), response['Images']))[-1][1]
        ami = latest_image['ImageId']
        block_device = None
        for mapping in latest_image['BlockDeviceMappings']:
            if 'Ebs' in mapping:
                if block_device is not None:
                    raise Exception('Multiple block devices found')
                block_device = mapping['DeviceName']
        if block_device is None:
            raise Exception('No block device found')
        print('Found AMI %s created %s with block device %s'%(ami, latest_image['CreationDate'], block_device), file=sys.stderr)

        tags = [{
            'ResourceType': 'instance',
            'Tags': [{'Key': 'Name', 'Value': "rr-test %s %s"%(self.distro_name, architecture)}]
        }]
        response = self.ec2.create_instances(ImageId=ami, InstanceType=machine_type,
            KeyName='rr-testing', MinCount=1, MaxCount=1,
            BlockDeviceMappings=[{'DeviceName': block_device, 'Ebs': {'VolumeSize': 32}}],
            InstanceInitiatedShutdownBehavior='terminate',
            SecurityGroups=['rr-testing'],
            TagSpecifications=tags)
        self.instance = response[0]
        print('Starting VM %s "%s"'%(self.instance.id, self.distro_name), file=sys.stderr)

    def wait_for_ssh(self):
        """Wait until the instance is ready to accept ssh commands."""
        self.instance.wait_until_running()
        self.instance.reload()
        print('Started VM %s "%s" at %s'%(self.instance.id, self.distro_name, self.instance.public_ip_address), file=sys.stderr)
        for retries in range(60):
            result = subprocess.run(self.ssh_command() + ['true'], stdin=subprocess.DEVNULL, stderr=subprocess.PIPE)
            if result.returncode == 0:
                self.ssh_ready = True
                return
            if (b'Connection refused' not in result.stderr and
                b'reset by peer' not in result.stderr and
                b'Connection timed out' not in result.stderr):
                raise Exception('SSH connection failed:\n%s'%result.stderr.decode('utf-8'))
            time.sleep(1)
        raise Exception('Too many retries, cannot connect via SSH')

    def ssh(self, cmd, input):
        """Run `cmd` (command + args list) via SSH and wait for it to finish.
           Command stdout and stderr are echoed to our stdout/stderr.
           If the command fails, throws an exception with the exit status.
           Returns nothing."""
        full_cmd = self.ssh_command() + cmd
        print('Running %s'%full_cmd, file=sys.stderr)
        process = subprocess.Popen(full_cmd, stdin=subprocess.PIPE)
        process.communicate(input=input, timeout=args.timeout)
        if process.returncode != 0:
            raise Exception('Command failed with %d'%process.returncode)

    def scp_from(self, options, src, dst):
        """Copies files from remote `src` to local `dst`."""
        full_cmd = ['scp'] + self.ssh_options() + options + ['%s:%s'%(self.ssh_dest(), src), dst]
        print('Running %s'%full_cmd, file=sys.stderr)
        subprocess.check_call(full_cmd)

    def ssh_command(self):
        return ['ssh'] + self.ssh_options() + [self.ssh_dest()]

    def ssh_options(self):
        return ['-i', self.keypair_pem_file,
                '-o', 'StrictHostKeyChecking=no',
                '-o', 'BatchMode=yes',
                '-o', 'ConnectTimeout=5',
                '-o', 'IdentitiesOnly=yes']

    def ssh_dest(self):
        return '%s@%s'%(self.user, self.instance.public_ip_address)

    def terminate(self):
        response = self.instance.terminate()
        if response['ResponseMetadata']['HTTPStatusCode'] != 200:
            print('Terminating VM %s failed: %s'%(self.instance_id, response), file=sys.stderr)
        self.instance.wait_until_terminated()

with open(args.distro_config_json, 'r') as f:
    distro_config = json.load(f)

with pathlib.Path(__file__).with_name('rr-testing.sh').open('rb') as f:
    rr_testing_script = f.read()

def get_config_lines(config_key):
    entry = distro_config.get(config_key)
    if isinstance(entry, str):
        return [entry]
    if isinstance(entry, list):
        return entry
    if entry is None:
        return []
    raise ValueError('Invalid config entry %s: %s' % (config_key, entry))

def get_config_lines_arch(config_key):
    return get_config_lines(config_key) + get_config_lines('%s_%s'%(config_key, args.architecture))

def config_script_function(config_key):
    lines = get_config_lines_arch(config_key)
    return ('function %s {\n%s\n}' % (config_key, '\n'.join(lines)))

if args.dist_files_dir and not distro_config.get('staticlibs', True):
    print('Dist builds must use staticlibs, aborting', file=sys.stderr)
    sys.exit(1)

machine_type = args.machine_type
if not machine_type:
    if args.architecture == 'x86_64':
        machine_type = 'c5.9xlarge'
    elif args.architecture == 'arm64':
        machine_type = 'c6g.8xlarge'

vm = Ec2Vm(machine_type, args.architecture, distro_config, args.keypair_pem_file)
success = False
try:
    vm.wait_for_ssh()
    exclude_tests = get_config_lines_arch('exclude_tests')
    full_script = '\n'.join(
        [
            config_script_function('setup_commands'),
            config_script_function('install_build_deps'),
            config_script_function('install_app_test_deps'),
            'git_revision=%s'%args.git_revision,
            'staticlibs=%s'%('TRUE' if distro_config.get('staticlibs', True) else 'FALSE'),
            'build_dist=%d'%(1 if args.dist_files_dir is not None else 0),
            # Firefox doesn't have release tarballs for Aarch64
            'test_firefox=%d'%(1 if args.architecture == 'x86_64' else 0),
            # libreoffice uses STREX
            'test_libreoffice=%d'%(1 if args.architecture == 'x86_64' else 0),
            'ctest_options="%s"'%' '.join('-E %s'%r for r in exclude_tests),
            'cpack_generators=%s'%args.cpack_generators
        ]).encode('utf-8') + b'\n' + rr_testing_script
    vm.ssh(['/bin/bash', '-s'], full_script)
    if args.dist_files_dir is not None:
        vm.scp_from(['-r'], '/tmp/dist', args.dist_files_dir)
    success = True
finally:
    if (not success and args.keep_vm_on_error) or args.keep_vm:
        if vm.ssh_ready:
            print('VM kept; connect with: %s'%(' '.join(vm.ssh_command())), file=sys.stderr)
        else:
            print('VM %s still starting up'%vm.instance.id)
    else:
        vm.terminate()
