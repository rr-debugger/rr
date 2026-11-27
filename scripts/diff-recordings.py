#!/usr/bin/env python3

import os
import sys
import subprocess

trace=sys.argv[1]

rr=os.path.join(os.environ["HOME"], "rr", "obj", "bin", "rr")
rr_env=os.environ.copy()
rr_env["RR_LOG"]="ReplaySession:debug"
rerun=subprocess.Popen([rr, "rerun", "--singlestep=event,icount,rip,rax,rbx,rcx,rdx,rsp,rsi,rdi,rbp,r8,r9,r10,r11,r12,r13,r14,15", trace],stdout=subprocess.PIPE,env=rr_env)
remix=subprocess.Popen([rr, "rerun", "-x", "--singlestep=event,icount,rip,rax,rbx,rcx,rdx,rsp,rsi,rdi,rbp,r8,r9,r10,r11,r12,r13,r14,15", trace],stdout=subprocess.PIPE,env=rr_env)

previous_line=""
while True:
    rerun_line = rerun.stdout.readline()
    remix_line = remix.stdout.readline()
    if rerun_line != remix_line:
        print("Output differs\nrerun: %s\nremix: %s\nprevious: %s"%(rerun_line, remix_line, previous_line))
        sys.exit(-1)
    previous_line = rerun_line
