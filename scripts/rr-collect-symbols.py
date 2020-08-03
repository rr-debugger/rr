#!/usr/bin/env python3

import errno
import glob
import os
import re
import shutil
import subprocess
import sys
import tempfile
from urllib.request import urlretrieve
from urllib.error import HTTPError, ContentTooShortError

# Usage: rr-collect-symbols.py <trace-dir> [<url> | <path>]
#
# Given a <url>, downloads the zip/.tar.zst file at <url>, uncompresses it,
# runs "gunzip" on any .gz files, and for any ELF files found whose build-ids
# match the build-id of an ELF file in the trace, moves it into the trace.
#
# Given a <path>, which must contain a .build-id directory with the usual
# structure (e.g. as Ubuntu and Fedora create under /usr/lib/debug), searches
# the directory tree for any ELF files whose build-ids match the build-id of
# an ELF file in the trace and copies them into the trace. <path> defaults to
# "/usr/lib/debug", which will grab any available system debuginfo files
# in Ubuntu and Fedora at least.
#
# This script assumes that the trace-dir has been packed via `rr pack` so all
# relevant files actually appear in the trace-dir.
# It also assumes rr is on the PATH.
#
# The debuginfo files are placed in the trace under a "debug" subdirectory,
# in a ".build-id" subdirectory with the usual structure.
#
# If a debuginfo file contains a .gnu_debugaltlink section then we also
# attempt to find the referenced file and copy it into the trace with the
# same file name as the .debug file, but with a .sup suffix.

if len(sys.argv) < 2:
    print("Usage: rr-collect-symbols.py <trace-dir> [<url> | <path>]", file=sys.stderr)
    sys.exit(1)
trace_dir = sys.argv[1]

if len(sys.argv) < 3:
    source = "/usr/lib/debug"
else:
    source = sys.argv[2]

rr_buildid = subprocess.Popen(["rr", "buildid"],
                              stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE)

def build_id_for(file):
    global rr_buildid
    rr_buildid.stdin.write(("%s\n"%file).encode('utf-8'))
    try:
        rr_buildid.stdin.flush()
    except BrokenPipeError:
        print("Can't write to rr, termination code %s"%rr_buildid.returncode, file=sys.stderr)
        sys.exit(2)
    return rr_buildid.stdout.readline().rstrip().decode('utf-8')

altref_regex = re.compile(rb"^\s+\[\s*0\]\s+(.*)");

def find_altref(file):
    proc = subprocess.Popen(["readelf", "-p", ".gnu_debugaltlink", file], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    try:
        for line in proc.stdout:
            m = altref_regex.match(line)
            if m:
                return m.group(1).rstrip()
    finally:
        proc.wait()
    return None

def find_altref_for_trace_file(trace_file, altref):
    proc = subprocess.Popen(["rr", "filename", trace_file], stdout=subprocess.PIPE)
    try:
        for line in proc.stdout:
            file = line.rstrip()
            altref_file = os.path.join(os.path.dirname(file), altref)
            if os.path.isfile(altref_file):
                return altref_file
    finally:
        proc.wait()
    return None

def mkdir_p(path):
    try:
        os.makedirs(path)
    except OSError as exc:
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            raise

def collect_trace_build_ids():
    ret = {}
    for file in glob.iglob("%s/mmap_*"%trace_dir):
        build_id = build_id_for(file)
        if build_id:
            ret[build_id] = True
            altref = find_altref(file)
            if altref:
                altref_file = find_altref_for_trace_file(file, altref)
                if not altref_file:
                    raise "Can't find alt file %s for %s"%(altref, file)
                dir = "%s/debug/.build-id/%s"%(trace_dir, build_id[:2])
                mkdir_p(dir)
                dst = "%s/%s.sup"%(dir, build_id[2:])
                subprocess.check_call(["cp", "--preserve", "-f", "--reflink=auto", altref_file, dst])
    return ret

trace_build_ids = collect_trace_build_ids()

def collect_archive(url):
    is_tar_zst = url.endswith(".tar.zst")
    tmp_dir = tempfile.mkdtemp(dir=trace_dir)
    if is_tar_zst:
        tmp_file_name = "%s/archive.tar.zst"%tmp_dir
    else:
        # Assume its a ZIP
        tmp_file_name = "%s/archive.zip"%tmp_dir
    try:
        (file, headers) = urlretrieve(url, tmp_file_name)
    except (HTTPError, ContentTooShortError) as exc:
        print("Failed to load archive %s: %s"%(url, exc), file=sys.stderr)
        sys.exit(2)
    if is_tar_zst:
        subprocess.check_call(["tar", "-C", tmp_dir, "-I", "zstd", "-xvf", file])
    else:
        subprocess.check_call(["unzip", "-d", tmp_dir, file])
    os.remove(file)

    for root, dirs, files in os.walk(tmp_dir):
        for name in files:
            file = os.path.join(root, name)
            if file.endswith(".gz"):
                subprocess.check_call(["gunzip", file])
                file = file[:-3]
            build_id = build_id_for(file)
            if build_id and build_id in trace_build_ids:
                dir = "%s/debug/.build-id/%s"%(trace_dir, build_id[:2])
                mkdir_p(dir)
                dst = "%s/%s.debug"%(dir, build_id[2:])
                os.rename(file, dst)
            else:
                os.remove(file)

    shutil.rmtree(tmp_dir)

def collect_filesystem(path):
    for root, dirs, files in os.walk(path):
        for name in files:
            file = os.path.join(root, name)
            if not os.path.islink(file):
                build_id = build_id_for(file)
                if build_id and build_id in trace_build_ids:
                    dir = "%s/debug/.build-id/%s"%(trace_dir, build_id[:2])
                    mkdir_p(dir)
                    dst = "%s/%s.debug"%(dir, build_id[2:])
                    subprocess.check_call(["cp", "--preserve", "-f", "--reflink=auto", file, dst])
                    altref = find_altref(file)
                    if altref:
                        altref_file = os.path.join(os.path.dirname(file), altref.decode('utf-8'))
                        dst = "%s/%s.sup"%(dir, build_id[2:])
                        subprocess.check_call(["cp", "--preserve", "-f", "--reflink=auto", altref_file, dst])

if re.search("^[^:/]+:", source):
    collect_archive(source)
else:
    collect_filesystem(source)

rr_buildid.terminate()
