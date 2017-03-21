# Overview

rr is a lightweight tool for recording and replaying execution of applications (trees of processes and threads).  More information about the project, including instructions on how to install, run, and build rr, is at [http://rr-project.org](http://rr-project.org).

Or go directly to the [installation and building instructions](https://github.com/mozilla/rr/wiki/Building-And-Installing).

Please contribute!  Make sure to review the [pull request checklist](/CONTRIBUTING.md) before submitting a pull request.

If you find rr useful, please [add a testimonial](https://github.com/mozilla/rr/wiki/Testimonials).

# System requirements

* Linux kernel ≥ 3.5 is required (for [seccomp-bpf](https://en.wikipedia.org/wiki/Seccomp)).
* rr currently requires an Intel CPU with [Nehalem](https://en.wikipedia.org/wiki/Nehalem_%28microarchitecture%29) (2010) or later microarchitecture.
* Running in a VM guest is supported, as long as the VM supports virtualization of hardware performance counters. (VMware and KVM are known to work; Xen works in theory but may be broken.)

