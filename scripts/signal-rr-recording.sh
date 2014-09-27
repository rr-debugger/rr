#!/usr/bin/bash

signal=$1
if [[ "$signal" == "" ]]; then
    echo "Usage: $0 <signal>" >&2
    echo "Sends <signal> to all processes being recorded by rr" >&2
    exit 1
fi

function signal_descendants { pid=$1
    for child in `ps -o pid= --ppid $pid`; do
        echo Sending $signal to $child
        kill -s $signal $child
        signal_descendants $child
    done
}

for rr_pid in `pidof rr` ; do
    if cat /proc/$rr_pid/cmdline | tr '\0' '\n' | head -n2 | tail -n1 | grep -qz '\(^record$\)\|/'  ; then
        signal_descendants $rr_pid
    fi
done
