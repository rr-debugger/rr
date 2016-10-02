[![Build Status (travis)](https://travis-ci.org/mozilla/rr.svg?branch=master "Travis")](https://travis-ci.org/mozilla/rr)

# overview
rr is a lightweight tool for recording and replaying execution of applications (trees of processes and threads).  More information about the project, including instructions on how to install, run, and build rr, is at [http://rr-project.org](http://rr-project.org).

Or go directly to the [installation and building instructions](https://github.com/mozilla/rr/wiki/Building-And-Installing).

Please contribute!  Make sure to review the [pull request checklist](/CONTRIBUTING.md) before submitting a pull request.

If you find rr useful, please [add a testimonial](https://github.com/mozilla/rr/wiki/Testimonials).

# system requirements
* Intel CPU with [Nehalem](https://en.wikipedia.org/wiki/Nehalem_%28microarchitecture%29) (2010) or later microarchitecture

 * VM with perf counter virtualization is ok
 * userspace: x86, x86-64
 * kernel: x86-64

* Linux with PTRACE_INTERRUPT support: ≥ 3.4
* (strongly encouraged) Linux with [seccomp-bpf](https://en.wikipedia.org/wiki/Seccomp) support: ≥ 3.5
