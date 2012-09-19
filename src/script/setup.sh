#!/bin/bash
echo "Disabling address space randomization...(sudo sysctl -w kernel.randomize_va_space=0)"
sudo sysctl -w kernel.randomize_va_space=0
echo "Adding permission to write to process memory...(sudo sysctl -w kernel.yama.ptrace_scope=0)"
sudo sysctl -w kernel.yama.ptrace_scope=0

