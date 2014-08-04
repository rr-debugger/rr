#!/usr/bin/bash

signal=$1
if [[ "$signal" == "" ]]; then
    echo "Usage: $0 <signal>" >&2
    echo "Sends <signal> to all processes being recorded by rr" >&2
    exit 1
fi

function signal_descendants { pid=$1
    for child in `ps -o pid= --ppid $pid`; do
        kill -s $signal $child
        signal_descendants $child
    done
}

for rr_pid in `pidof rr` ; do
    if grep -qz '^record$' /proc/$rr_pid/cmdline ; then
        signal_descendants $rr_pid
    fi
done
