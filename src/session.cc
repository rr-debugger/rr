/* -*- Mode: C++; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

//#define DEBUGTAG "Session"

#include "session.h"

#include <syscall.h>
#include <sys/prctl.h>

#include "emufs.h"
#include "log.h"
#include "task.h"
#include "util.h"

using namespace std;

AddressSpace::shr_ptr
Session::create_vm(Task* t)
{
	AddressSpace::shr_ptr as(new AddressSpace(t, *this));
	as->insert_task(t);
	sas.insert(as.get());
	return as;
}

AddressSpace::shr_ptr
Session::clone(AddressSpace::shr_ptr vm)
{
	AddressSpace::shr_ptr as(new AddressSpace(*vm));
	sas.insert(as.get());
	return as;
}

Task*
Session::clone(Task* p, int flags, void* stack, void* tls, void* cleartid_addr,
	       pid_t new_tid, pid_t new_rec_tid)
{
	Task* c = p->clone(flags, stack, tls, cleartid_addr, new_tid,
			   new_rec_tid);
	track(c);
	return c;
}

TaskGroup::shr_ptr
Session::create_tg(Task* t)
{
	TaskGroup::shr_ptr tg(new TaskGroup(t->rec_tid, t->tid));
	tg->insert_task(t);
	return tg;
}

void
Session::dump_all_tasks(FILE* out)
{
	out = out ? out : stderr;

	for (auto as : sas) {
		auto ts = as->task_set();
		Task* t = *ts.begin();
		// XXX assuming that address space == task group,
		// which is almost certainly what the kernel enforces
		// too.
		fprintf(out, "\nTask group %d, image '%s':\n",
			t->tgid(), as->exe_image().c_str());
		for (auto tsit = ts.begin(); tsit != ts.end(); ++tsit) {
			(*tsit)->dump(out);
		}
	}
}

Task*
Session::find_task(pid_t rec_tid)
{
	auto it = tasks().find(rec_tid);
	return tasks().end() != it ? it->second : nullptr;
}

void
Session::kill_all_tasks()
{
	while (!task_map.empty()) {
		Task* t = task_map.rbegin()->second;
		LOG(debug) <<"Killing "<< t->tid <<"("<< t <<")";
		t->kill();
		delete t;
	}
}

void
Session::on_destroy(AddressSpace* vm)
{
	assert(vm->task_set().size() == 0);
	sas.erase(vm);
}

void
Session::on_destroy(Task* t)
{
	task_map.erase(t->rec_tid);
	task_priority_set.erase(make_pair(t->priority, t));
}

void
Session::track(Task* t)
{
	task_map[t->rec_tid] = t;
	task_priority_set.insert(make_pair(t->priority, t));
}

void
Session::update_task_priority(Task* t, int value)
{
	task_priority_set.erase(make_pair(t->priority, t));
	t->priority = value;
	task_priority_set.insert(make_pair(t->priority, t));
}

Task*
RecordSession::create_task(const struct args_env& ae, shr_ptr self)
{
	assert(self.get() == this);
	Task* t = Task::spawn(ae, *this);
	track(t);
	t->session_record = self;
	return t;
}

/*static*/ RecordSession::shr_ptr
RecordSession::create(const string& exe_path)
{
	shr_ptr session(new RecordSession());
	session->trace_ofstream = TraceOfstream::create(exe_path);
	return session;
}

static void
remap_shared_mmap(Task* t, struct current_state_buffer* state,
		  ReplaySession& session,
		  const Mapping& m, const MappableResource& r)
{
	LOG(debug) <<"    remapping shared region at "<< m.start <<"-"<< m.end;
	remote_syscall2(t, state, SYS_munmap, m.start, m.num_bytes());
	// NB: we don't have to unmap then re-map |t->vm()|'s idea of
	// the emulated file mapping.  Though we'll be remapping the
	// *real* OS mapping in |t| to a different file, that new
	// mapping still refers to the same *emulated* file, with the
	// same emulated metadata.

	auto emufile = session.emufs().at(r.id);
	// TODO: this duplicates some code in replay_syscall.cc, but
	// it's somewhat nontrivial to factor that code out.
	int remote_fd;
	{
		string path = emufile->proc_path();
		struct restore_mem restore_path;
		void* child_path = push_tmp_str(t, state, path.c_str(),
						&restore_path);
		int oflags = (MAP_SHARED & m.flags) && (PROT_WRITE & m.prot) ?
			     O_RDWR : O_RDONLY;
		remote_fd = remote_syscall2(t, state, SYS_open,
					    child_path, oflags);
		if (0 > remote_fd) {
			FATAL() <<"Couldn't open "<< path <<" in tracee";
		}
		pop_tmp_mem(t, state, &restore_path);
	}
	void* addr = (void*)
		     remote_syscall6(t, state, SYS_mmap2,
				     m.start, m.num_bytes(),
				     m.prot,
				     // The remapped segment *must* be
				     // remapped at the same address,
				     // or else many things will go
				     // haywire.
				     m.flags | MAP_FIXED,
				     remote_fd, m.offset / page_size());
	ASSERT(t, addr == m.start);

	remote_syscall1(t, state, SYS_close, remote_fd);
}

ReplaySession::shr_ptr
ReplaySession::clone()
{
	LOG(debug) <<"Deepforking ReplaySession "<< this <<" ...";

	shr_ptr session(new ReplaySession());
	LOG(debug) <<"  deepfork session is "<< session.get();
	session->tracees_consistent = tracees_consistent;
	session->emu_fs = emu_fs->clone();
	assert(!last_debugged_task);
	session->tgid_debugged = tgid_debugged;
	session->trace_ifstream = trace_ifstream->clone();

	for (auto vm : sas) {
		Task* some_task = *vm->task_set().begin();
		pid_t tgid = some_task->tgid();
		Task* group_leader = find_task(tgid);
		LOG(debug) <<"  forking tg "<< tgid
			   <<" (real: "<< group_leader->real_tgid() <<")";

		if (group_leader->is_probably_replaying_syscall()) {
			group_leader->finish_emulated_syscall();
		}

		Task* clone_leader = group_leader->os_fork_into(session.get());
		clone_leader->session_replay = session;
		session->track(clone_leader);
		LOG(debug) <<"  forked new group leader "<< clone_leader->tid;

		struct current_state_buffer state;
		prepare_remote_syscalls(clone_leader, &state);

		for (auto& kv : clone_leader->vm()->memmap()) {
			const Mapping& m = kv.first;
			const MappableResource& r = kv.second;
			if (!r.is_shared_mmap_file()) {
				continue;
			}
			remap_shared_mmap(clone_leader, &state, *session,
					  m, r);
		}

		for (auto t : group_leader->task_group()->task_set()) {
			if (group_leader == t) {
				continue;
			}
			LOG(debug) <<"    cloning "<< t->rec_tid;

			if (t->is_probably_replaying_syscall()) {
				t->finish_emulated_syscall();
			}
			Task* t_clone = t->os_clone_into(clone_leader, &state);
			t_clone->session_replay = session;
			session->track(t_clone);
			t_clone->copy_state(t);
		}
		finish_remote_syscalls(clone_leader, &state);

		LOG(debug) <<"  restoring group-leader state ...";
		clone_leader->copy_state(group_leader);
	}
	assert(session->vms().size() > 0);
	return session;
}

Task*
ReplaySession::create_task(const struct args_env& ae, shr_ptr self,
			   pid_t rec_tid)
{
	assert(self.get() == this);
	Task* t = Task::spawn(ae, *this, rec_tid);
	track(t);
	t->session_replay = self;
	return t;
}

void
ReplaySession::gc_emufs()
{
	emu_fs->gc(*this);
}

void
ReplaySession::restart()
{
	kill_all_tasks();
	assert(tasks().size() == 0 && vms().size() == 0);
	last_debugged_task = nullptr;
	tgid_debugged = 0;
	tracees_consistent = false;

	gc_emufs();
	assert(emufs().size() == 0);

	trace_ifstream->rewind();
}

/*static*/ ReplaySession::shr_ptr
ReplaySession::create(int argc, char* argv[])
{
	shr_ptr session(new ReplaySession());
	session->emu_fs = EmuFs::create();
	session->trace_ifstream = TraceIfstream::open(argc, argv);
	return session;
}
