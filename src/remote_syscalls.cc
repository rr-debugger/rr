/* -*- Mode: C++; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

//#define DEBUGTAG "RemoteSyscalls"

#include "remote_syscalls.h"

#include "log.h"
#include "task.h"
#include "util.h"

void
AutoRestoreMem::init(const byte* mem, ssize_t num_bytes)
{
	len = num_bytes;
	saved_sp = (void*)remote.regs().sp();

	remote.regs().set_sp(remote.regs().sp() - len);
	remote.task()->set_regs(remote.regs());
	addr = (void*)remote.regs().sp();

	data = (byte*)malloc(len);
	remote.task()->read_bytes_helper(addr, len, data);

	if (mem) {
		remote.task()->write_bytes_helper(addr, len, mem);
	}
}

AutoRestoreMem::~AutoRestoreMem()
{
	assert(saved_sp == (byte*)remote.regs().sp() + len);

	remote.task()->write_bytes_helper(addr, len, data);
	free(data);

	remote.regs().set_sp(remote.regs().sp() + len);
	remote.task()->set_regs(remote.regs());
}

AutoRemoteSyscalls::AutoRemoteSyscalls(Task* t)
	: t(t)
	, initial_regs(t->regs())
	, initial_ip(t->ip())
	, pending_syscallno(-1)
{
	// Inject syscall instruction, saving previous insn (fragment)
	// at $ip.
	t->read_bytes(initial_ip, code_buffer);
	t->write_bytes(initial_ip, syscall_insn);
}

AutoRemoteSyscalls::~AutoRemoteSyscalls()
{
	restore_state_to(t);
}

void
AutoRemoteSyscalls::restore_state_to(Task* t)
{
	// Restore stomped insn (fragment).
	t->write_bytes(initial_ip, code_buffer);
	// Restore stomped registers.
	t->set_regs(initial_regs);
}

// TODO de-dup
static void advance_syscall(Task* t)
{
	do {
		t->cont_syscall();
	} while (t->is_ptrace_seccomp_event() || SIGCHLD == t->pending_sig());
	assert(t->ptrace_event() == 0);
}

long
AutoRemoteSyscalls::syscall_helper(SyscallWaiting wait, int syscallno,
                                   Registers& callregs)
{
	callregs.set_syscallno(syscallno);
	t->set_regs(callregs);

	advance_syscall(t);

	ASSERT(t, t->regs().original_syscallno() == syscallno)
		<<"Should be entering "<< t->syscallname(syscallno)
		<<", but instead at "<< t->syscallname(t->regs().original_syscallno());

	// Start running the syscall.
	pending_syscallno = syscallno;
	t->cont_syscall_nonblocking();
	if (WAIT == wait) {
		return wait_syscall(syscallno);
	}
	return 0;
}

long
AutoRemoteSyscalls::wait_syscall(int syscallno)
{
	ASSERT(t, pending_syscallno == syscallno);

	// Wait for syscall-exit trap.
	t->wait();
	pending_syscallno = -1;

	ASSERT(t, t->regs().original_syscallno() == syscallno)
		<<"Should be entering "<< t->syscallname(syscallno)
		<<", but instead at "<< t->syscallname(t->regs().original_syscallno());

	return t->regs().syscall_result_signed();
}
