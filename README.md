If you find rr useful, please [add a testimonial](https://github.com/mozilla/rr/wiki/Testimonials).

# System requirements

* Linux kernel ≥ 3.5 is required (for [seccomp-bpf](https://en.wikipedia.org/wiki/Seccomp)).
* rr currently requires an Intel CPU with [Nehalem](https://en.wikipedia.org/wiki/Nehalem_%28microarchitecture%29) (2010) or later microarchitecture.
* Running in a VM guest is supported, as long as the VM supports virtualization of hardware performance counters. (VMWare and KVM are known to work; Xen works in theory but may be broken.)

