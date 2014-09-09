/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef CONFIG_H_
#define CONFIG_H_

#include <inttypes.h>

/**
 * The following parameters define the default scheduling parameters.
 * The recorder scheduler basically works as follows
 *
 *  0. Find a task A with a pending event.
 *  1. If A was the last task scheduled, decrease its "max-event"
 *     counter.
 *  2. Program an HPC interrupt for A that will fire after "max-rbc"
 *     retired conditional branches (or so, it may not be precise).
 *  3. Resume the execution of A.
 *
 * The next thing that will occur is another scheduling event, after
 * which one of two things happens
 *
 *  0. Task A triggers a trace event in rr, which could be a signal,
 *     syscall entry/exit, HPC interrupt, ...
 *  1. Some other task triggers an event.
 *
 * And then we make another scheduling decision.
 *
 * Like in most task schedulers, there are conflicting goals to
 * balance.  Lower max-rbc / max-events generally makes the
 * application more "interactive", generally speaking lower latency.
 * (And wrt catching bugs, this setting generally creates more
 * opportunity for bugs to arise in multi-threaded/process
 * applications.)  This comes at the cost of more overhead from
 * scheduling and context switching.  Higher max-rbc / max-events
 * generally gives the application higher throughput.
 *
 * The rr scheduler is relatively dumb compared to modern OS
 * schedulers, but the default parameters are configured to achieve
 *
 *  o IO-heavy tasks are relatively quickly switched, in the hope this
 *    improves latency.
 *  o CPU-heavy tasks are given an O(10ms) timeslice before being
 *    switched.
 *  o Keep max number of HPC interrupts small to avoid overhead.
 *
 * In addition to all the aforementioned deficiencies, using retired
 * conditional branches to compute timeslices is quite crude, since
 * they don't correspond to any unit of time in general.  Hopefully
 * that can be improved, but empirical data from Firefox demonstrate,
 * surprisingly consistently, a distribution of insns/rcb massed
 * around 10.  Somewhat arbitrarily guessing ~4cycles/insn on average
 * (fair amount of pointer chasing), that implies
 *
 *  10ms = .01s = x rcb * (10insn / rcb) * (4cycle / insn) * (1s / 2e9cycle)
 *  x = 500000rcb / 10ms
 *
 * We'll arbitrarily decide to allow 10 max successive events for
 * latency reasons.  To try to keep overhead lower (since trace traps
 * are heavyweight), we'll give each task a relatively large 50ms
 * timeslice.  This works out to
 *
 *   50ms * (500000rcb / 10ms) / 10event = 250000 rbc / event
 */
#define DEFAULT_MAX_RBC 250000ULL
#define DEFAULT_MAX_EVENTS 10

#endif /* CONFIG_H_ */
