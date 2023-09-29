# Overview

[![Build status](https://badge.buildkite.com/43782b9c8f7c98ed8a9ba1e82c3baeba59783b675fc4d4c9e4.svg?branch=master)](https://buildkite.com/julialang/rr)

rr is a lightweight tool for recording, replaying and debugging execution of applications (trees of processes and threads).
Debugging extends gdb with very efficient reverse-execution, which in combination with standard gdb/x86 features like hardware data watchpoints, makes debugging much more fun. More information about the project, including instructions on how to install, run, and build rr, is at [https://rr-project.org](https://rr-project.org). The best technical overview is currently the paper [Engineering Record And Replay For Deployability: Extended Technical Report](https://arxiv.org/pdf/1705.05937.pdf).

Or go directly to the [installation and building instructions](https://github.com/rr-debugger/rr/wiki/Building-And-Installing).

Please contribute!  Make sure to review the [pull request checklist](/CONTRIBUTING.md) before submitting a pull request.

If you find rr useful, please [add a testimonial](https://github.com/rr-debugger/rr/wiki/Testimonials).

rr development is sponsored by [Pernosco](https://pernos.co) and was originated by [Mozilla](https://www.mozilla.org).

# System requirements

* a reasonable new Linux kernel
  * recent versions require >= 4.7 (for support of `__WALL` in `waitid()`)
  * rr up to 5.6 required >= 3.11 (for `PTRACE_SETSIGMASK`)
* rr currently requires either:
  * An Intel CPU with [Nehalem](https://en.wikipedia.org/wiki/Nehalem_%28microarchitecture%29) (2010) or later microarchitecture.
  * Certain AMD Zen or later processors (see https://github.com/rr-debugger/rr/wiki/Zen)
  * Certain AArch64 microarchitectures (e.g. ARM Neoverse N1 or the Apple Silicon M-series)
* Running in a VM guest is supported, as long as the VM supports virtualization of hardware performance counters. (VMware and KVM are known to work; Xen does not.)
