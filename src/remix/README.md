# Tools

Tool code runs in the address space of each tracee process. Tool code and the remix framework run in a dedicated memory region guaranteed not to be used by the tracee. When a tool is present, whenever rr needs to run code in the tracee, instead of using `PTRACE_CONT` etc we pass control to remix which generates translated code from the application binary code and runs that instead.

Each tool is compiled to a `librrremix_...Tool.so` library, a self-contained ELF object with no dependencies and only a restricted set of relocations supported. Each tool library contains the DynamoRio assembler/disassembler, a minimal libc-like runtime, the remix framework, and the tool-specific code. rr's `RemixCommand` is responsible for creating a `RemixModule` for every tracee process that needs one --- one `RemixModule` per rr `AddressSpace`. `RemixModule` is responsible for handle rr's requests to execute code in the tracee. It loads the tool library into the tracee address space using a custom tiny ELF loader that writes the library into place, with relocations. `RemixModule` communicates with the tool code by executing it with `PTRACE_CONT` with the RIP set to known symbols from the ELF symbol table (e.g. `remix_execute`) and parameters set in tracee registers.

There is one instance of the tool library in each tracee address space (process). Tracee `execve` creates a new tool instance. Tracee `fork` forks the tool instance. Depending on the tool, multiple instances may need to communicate via shared memory or some other mechanism. Each tool instance has direct access to all tracee memory (for that process), and tools can make unrestricted system calls.

Remix tools must preserve bit-for-bit identical tracee state. I.e., every time we finish running some tracee code and have arrived at a stop (see below), the contents of tracee memory and registers (outside the remix reserved memory area) exactly match the values they would have had if we had run the tracee on the CPU directly. This is necessary to ensure accurate replay, but it also means we can switch between remix execution and native execution at any time, or even unload one remix module and load another one. We can also debug remix bugs by examining the differences in state between remix execution and native execution at fine granularity.

# Fragments

A sequence of consecutive application instructions is translated into a `Fragment`. We keep a cache of translated `Fragment`s indexed by the starting PC. A loop in `remix_execute` repeatedly reads the current application PC, looks up the cache, generates a new fragment for the PC if there isn't one already, and then invokes the fragment, advancing application state. The application code ranges for fragments can overlap.

A fragment always either executes all its instructions or none; we never exit a fragment after some but not all of its instructions have executed. We can do this because during replay we know if and when a signal will be delivered, so we can always end a fragment where it would exit due to a signal. This simplifies translation and speeds up our generated code, because within a fragment we can move instructions around and keep values in registers without worrying about early exits.

## Stopping

To support replay we support four different stopping conditions for each call to `remix_execute`.

- Stop just before the next syscall instruction is entered (`STOP_AT_SYSCALL`)

- Stop when execution reaches a given PC (`STOP_AT_IP`)

- Stop when execution reaches a given PC with given register values and RCB count (`STOP_AT_TARGET`)

- Stop when execution reaches a given PC and emulate it (`STOP_AT_IP_EMULATE`)

- Stop when execution reaches a given PC and RSI is an invalid address (`STOP_AT_BREAKPOINT_FAULT`)

The condition data is stored in `remix_target_` globals where it can be accessed easily by generated code.

Stopping when the next syscall instruction is entered is easy. Syscall instructions are translated to code which checks the current stopping condition and executes a stop if we're supposed to, otherwise actually performs the syscall.

For the other cases, we ensure there are no fragments containing the given PC except for one fragment starting at the given PC: any fragment covering code before the PC must end at the PC. The fragment starting at the given PC starts by computing whether the stopping condition has been reached; if it has, it sets the "stopped" flag and exits immediately with no other side effects, otherwise it continues.

## Preconditions

On entry to a fragment:

- All registers match application registers, except for R8-R11 which have arbitrary values and (of course) RIP.
- The contents of `remix_registers`'s R8-R11, and non-general-purpose registers except RIP and RFLAGS, match the application registers.
- Application x87/MMX/SSE/AVX state matches CPU state.

Generally these conditions hold during a fragment, but we temporarily load application values into R8-R11 just before they're used. We may also load R8-R11 with the RIP of the start of the fragment, to support RIP-relative addressing.

We choose R8-R11 as our fixed scratch registers to simplify things. These registers are not much used,
so it doesn't impose much overhead to have to load and spill them. No instructions implicitly use them ...
except `syscall` (argh!). Using fixed registers means we can write assembly stubs just once.

Remix libraries cannot use x87 code or otherwise alter x87 state because this state is not saved or restored when transitioning between application and remix code. They can use XMM/YMM registers providing they call `ensure_mm_state_saved` before such usage. MXCSR is always in its default state while running remix code.

## Translate/Execute

We only generate a fragment when we're about to execute it. We can actually generate a series of connected fragments and then execute them all at once: whenever we execute a fragment ending in a direct unconditional branch or call, we know the next fragment to be executed, and if it's not already translated, we go ahead and translate that fragment too. The goal is to minimize the number of context switches between generationg translations and executing translated code --- but without ever translating code that doesn't execute.

`generate_one_fragment` appends generated code to the code-buffer at `code_buffer.next()` and saves the translation metadata for later lookup. If the fragment ends in a direct transfer to some untranslated PC, we return that in `GeneratedFragment::next_pc`; the next fragment will be appended directly at `code_buffer.next()`, so the generated code can fall through to it.

When `run_fragment` ends, either we've reached the stopping condition or more code generation is needed. In the latter case `remix_registers.rip` will have been set to the PC we're about to enter and need a translation for. `patch_state` may have been set up to patch a previously-executed fragment with the address of the next fragment.

Translations are generated into a linear ever-growing code buffer mapped RWX into the tool address space within each tracee process. When the buffer fills up, we simply flush the entire thing and start over to keep things simple.

## `run_fragment` Preconditions/Postconditions

On entry to and exit from `run_fragment`, `remix_registers` is correct for all application registers.

## Fragment Ends

There are the following cases:

### Transfer To Fixed PC

This covers fragments ending in direct jump and call instructions and fragments that end for other reasons but transfer control to the next instruction. If the destination PC has already been translated we can emit a final jump instruction to its translation, otherwise `generate_one_fragment` returns that PC and the translated code just falls through to the translation of the next fragment (which will be generated immediately).

### Conditional Branch

We generate the fragment, ending with code that performs the conditional branch and jumps to "taken"/"not taken" stubs. Then we run the already generated fragment(s) until we reach the conditional branch, so that we know which way it's going to go the first time it's executed.

We then do a case analysis to emit optimal code based on what we know. For each of the taken/not-taken destinations, either it has already been translated or it has not. If the path the first execution follows has not already been translated, we will fall through to the next fragment. If the destination of other path has not been translated, we emit code for it that jumps to a stub that when taken will exit from `run_fragment`.

The RCB counter is updated in each fragment ending with a conditional branch. We try to emit an `inc` instruction before a fragment instruction that sets the arithmetic flags without reading them; if that doesn't work, we emit a `mov`/`lea`/`mov` sequence that increments the counter without affecting flags.

### Indirect Jump/Call/Return

We emit code to get the computed destination PC into a scratch register and jump to a stub. That stub does an indirect lookup into a direct-mapped cache of indirect branch targets. If it's in the cache, we directly jump to the translation. If it's not in the cache, we do a lookup of the full translation hashtable. If a translation is found we update the cache and jump to the translation. If no translation is found, we return from `run_fragment` with the new PC in `remix_registers.rip` and the patching state set up to store into the cache the address of the new translation. We use 8 different stubs, to trade off instruction cache vs BTB entries.

## Fragment Invalidation

We keep a table mapping invalidated PCs to the first fragment generated for that PC. When a `Translation` is invalidated, if that table has no entry (first invalidation of this PC), we create the entry, otherwise we overwrite the current fragment with a jump to the first fragment. In either case we overwrite the first fragment with a jump to a stub that exits `run_fragment` with `patch_state` set to replace the first fragment with a direct jump to the new fragment. This approach ensures even if a PC is invalidated many times, at most two extra jumps are required for any control transfer to reach the currently-valid translation.

This requires each fragment to have enough space for a jump to a stub, i.e. the minimum fragment size is 5 bytes.

## Self-modifying Code

We use a W^X model. We monitor `mprotect`, `mmap` and `mremap` calls; when pages are mapped, unmapped or made writeable, invalidate all translations overlapping those pages. This is enough to handle code that really is W^X. For pages that are WX, we make them W^X internally. When executing code in a WX page, we use `mprotect` to make it read-only. Writes to the page will trigger SIGSEGV, and our handle will flip to the page to writable, invalidate its translations, and resume execution. When asked to create a translation for code in a writeable page, we reset the page to read-only. All fragments overlapping a WX page are restricted so that an instruction with a write operand must be the last instruction in a fragment, so if that instruction modifies the following instruction we still execute correctly --- invalidating the translation of the fragment for the following instruction. (We can only invalidate at the start of a fragment.)

# Hints for writing tools

Because rr is single-core only, only one thread in the replay can be running at a time so data races aren't a problem.

## Instrumentation types

For very short instrumentation code, or code that depends heavily on details of the instruction you're instrumenting (e.g. calculating the effective address generated by a memory operand), generate inline code before and/or after the instruction.

For longer and more repetitive instrumentation code, use helper functions implemented in assembly in `...Tool_stubs.S`. Declare `extern AsmStub <function_name>` inside an `extern "C"` block in your tool and generate instrumentation code that calls into those stubs (see below). Give each stub a calling convention that takes parameters in fixed scratch registers, and reserve those scratch registers in your generated instrumentation code. Stub calls are cheap, and inlining lots of instrumentation code bloats caches and slows down code translation.

When your stub does something really complex (hopefully only in infrequent situations, otherwise your instrumentation is sure to be slow), it can call out to C++. Assembly helper stubs can call into C++ via either `prepare_enter_cpp`, or `prepare_enter_cpp_fast` if the code is guaranteed not to use any registers other than the general-purpose registers.

## Calling helper stubs

RSP always matches the application RSP while we execute translated code. Thus, instrumentation cannot call helper functions using regular `call` instructions, as these would corrupt application stack contents below RSP, whose values are relevant in some cases (leaf functions, reads from uninitialized stack memory). Instead we use a link-register approach, generating code that looks like this:
```
    lea return_address(%rip),%r11
    jmp helper_function
return_address:
    ...

helper_function:
    ... do helper function stuff that preserves r11 ...
    jmp *%r11
```
Surprisingly, at least on Skylake this is very efficient and somehow seems to avoid indirect branch misprediction.

## Handling flags

EFLAGS matches the application EFLAGS while we execute translated code. Thus instrumentation must avoid altering flags, which is particularly annoying because saving and restoring flags is expensive on x86. In some cases you can choose instructions that avoid modifying flags; e.g. our instrumentation often uses `lea` as an `add` instruction that does not modify flags. Often instrumentation can be placed just before an application instruction that modifies flags, in which case flags don't have to be saved and restored; to help with this, remix performs some simple dataflow analysis and computes for each instruction `AnalysisBase::arith_flags_live_at_end`. When flags must be saved and restored, we have `SAVE_FLAGS` and `RESTORE_FLAGS` macros that save RAX to R11 and then save arithmetic flags to RAX (using `lahf; seto %al`), and undo that. You can also often remove redundant restore/save pairs when instrumenting multiple instructions in the same fragment. In some cases we use four versions of each helper stub, for all combinations of "save flags at start" x "restore flags at end".

## Debugging

`RR_LOG=remix` will dump generated code.

`rr remix -g` will start applying instrumentation at some particular rr event. This is often useful for narrowing down bugs.

Use `remix_assert` to narrow down bugs.

When a remix tool crashes, rr will print instructions for activating the emergency debugger, which will let you inspect the state of the remix tool and the tracee process.