/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

//#define DEBUGTAG "Session"

#include "session.h"

#include <syscall.h>
#include <sys/prctl.h>

#include <algorithm>

#include "emufs.h"
#include "log.h"
#include "remote_syscalls.h"
#include "task.h"
#include "util.h"

using namespace rr;
using namespace std;

Session::Session() : tracees_consistent(false) {
  LOG(debug) << "Session " << this << " created";
}

Session::~Session() {
  kill_all_tasks();
  LOG(debug) << "Session " << this << " destroyed";
}

void Session::after_exec() {
  if (tracees_consistent) {
    return;
  }
  tracees_consistent = true;
  // Reset rbcs for all Tasks (there should only be one).
  for (auto task = tasks().begin(); task != tasks().end(); ++task) {
    task->second->flush_inconsistent_state();
  }
}

AddressSpace::shr_ptr Session::create_vm(Task* t, const std::string& exe) {
  AddressSpace::shr_ptr as(new AddressSpace(t, exe, *this));
  as->insert_task(t);
  sas.insert(as.get());
  return as;
}

AddressSpace::shr_ptr Session::clone(AddressSpace::shr_ptr vm) {
  AddressSpace::shr_ptr as(new AddressSpace(*vm));
  as->session = this;
  sas.insert(as.get());
  return as;
}

Task* Session::clone(Task* p, int flags, void* stack, void* tls,
                     void* cleartid_addr, pid_t new_tid, pid_t new_rec_tid) {
  Task* c = p->clone(flags, stack, tls, cleartid_addr, new_tid, new_rec_tid);
  track(c);
  return c;
}

TaskGroup::shr_ptr Session::create_tg(Task* t) {
  TaskGroup::shr_ptr tg(new TaskGroup(t->rec_tid, t->tid));
  tg->insert_task(t);
  return tg;
}

void Session::dump_all_tasks(FILE* out) {
  out = out ? out : stderr;

  for (auto as : sas) {
    auto ts = as->task_set();
    Task* t = *ts.begin();
    // XXX assuming that address space == task group,
    // which is almost certainly what the kernel enforces
    // too.
    fprintf(out, "\nTask group %d, image '%s':\n", t->tgid(),
            as->exe_image().c_str());
    for (auto tsit = ts.begin(); tsit != ts.end(); ++tsit) {
      (*tsit)->dump(out);
    }
  }
}

Task* Session::find_task(pid_t rec_tid) {
  auto it = tasks().find(rec_tid);
  return tasks().end() != it ? it->second : nullptr;
}

void Session::kill_all_tasks() {
  while (!task_map.empty()) {
    Task* t = task_map.rbegin()->second;
    LOG(debug) << "Killing " << t->tid << "(" << t << ")";
    t->kill();
    delete t;
  }
}

void Session::on_destroy(AddressSpace* vm) {
  assert(vm->task_set().size() == 0);
  assert(sas.end() != sas.find(vm));
  sas.erase(vm);
}

void Session::on_destroy(Task* t) {
  task_map.erase(t->rec_tid);
  if (t->in_round_robin_queue) {
    auto iter =
        find(task_round_robin_queue.begin(), task_round_robin_queue.end(), t);
    task_round_robin_queue.erase(iter);
  } else {
    task_priority_set.erase(make_pair(t->priority, t));
  }
}

void Session::track(Task* t) {
  task_map[t->rec_tid] = t;
  assert(!t->in_round_robin_queue);
  task_priority_set.insert(make_pair(t->priority, t));
}

void Session::update_task_priority(Task* t, int value) {
  if (t->in_round_robin_queue) {
    t->priority = value;
    return;
  }
  task_priority_set.erase(make_pair(t->priority, t));
  t->priority = value;
  task_priority_set.insert(make_pair(t->priority, t));
}

void Session::schedule_one_round_robin(Task* t) {
  if (!task_round_robin_queue.empty()) {
    return;
  }

  for (auto iter : task_priority_set) {
    if (iter.second != t) {
      task_round_robin_queue.push_back(iter.second);
      iter.second->in_round_robin_queue = true;
    }
  }
  task_round_robin_queue.push_back(t);
  t->in_round_robin_queue = true;
  task_priority_set.clear();
}

Task* Session::get_next_round_robin_task() {
  if (task_round_robin_queue.empty()) {
    return nullptr;
  }

  return task_round_robin_queue.front();
}

void Session::remove_round_robin_task() {
  assert(!task_round_robin_queue.empty());

  Task* t = task_round_robin_queue.front();
  task_round_robin_queue.pop_front();
  if (t) {
    t->in_round_robin_queue = false;
    task_priority_set.insert(make_pair(t->priority, t));
  }
}

Task* RecordSession::create_task(const struct args_env& ae, shr_ptr self) {
  assert(self.get() == this);
  Task* t = Task::spawn(ae, *this);
  track(t);
  return t;
}

/*static*/ RecordSession::shr_ptr RecordSession::create(
    const string& exe_path) {
  shr_ptr session(new RecordSession());
  session->trace_ofstream = TraceOfstream::create(exe_path);
  return session;
}

static void remap_shared_mmap(AutoRemoteSyscalls& remote,
                              ReplaySession& session, const Mapping& m,
                              const MappableResource& r) {
  LOG(debug) << "    remapping shared region at " << m.start << "-" << m.end;
  remote.syscall(syscall_number_for_munmap(remote.arch()), m.start, m.num_bytes());
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
    AutoRestoreMem child_path(remote, path.c_str());
    int oflags =
        (MAP_SHARED & m.flags) && (PROT_WRITE & m.prot) ? O_RDWR : O_RDONLY;
    remote_fd =
      remote.syscall(syscall_number_for_open(remote.arch()), static_cast<void*>(child_path), oflags);
    if (0 > remote_fd) {
      FATAL() << "Couldn't open " << path << " in tracee";
    }
  }
  // XXX this condition is x86/x64-specific, I imagine.
  bool page_offset_mmap_in_use = has_mmap2_syscall(remote.arch());
  void* addr= 
    (void*)remote.syscall(page_offset_mmap_in_use
                          ? syscall_number_for_mmap2(remote.arch())
                          : syscall_number_for_mmap(remote.arch()),
                          m.start, m.num_bytes(), m.prot,
                          // The remapped segment *must* be
                          // remapped at the same address,
                          // or else many things will go
                          // haywire.
                          m.flags | MAP_FIXED, remote_fd,
                          page_offset_mmap_in_use
                          ? m.offset / page_size()
                          : m.offset);
  ASSERT(remote.task(), addr == m.start);

  remote.syscall(syscall_number_for_close(remote.arch()), remote_fd);
}

ReplaySession::~ReplaySession() {
  // We won't permanently leak any OS resources by not ensuring
  // we've cleaned up here, but sessions can be created and
  // destroyed many times, and we don't want to temporarily hog
  // resources.
  kill_all_tasks();
  assert(tasks().size() == 0 && vms().size() == 0);
  gc_emufs();
  assert(emufs().size() == 0);
}

ReplaySession::shr_ptr ReplaySession::clone() {
  LOG(debug) << "Deepforking ReplaySession " << this << " ...";

  shr_ptr session(new ReplaySession());
  LOG(debug) << "  deepfork session is " << session.get();
  session->tracees_consistent = tracees_consistent;
  session->emu_fs = emu_fs->clone();
  assert(!last_debugged_task);
  session->tgid_debugged = tgid_debugged;
  session->trace_ifstream = trace_ifstream->clone();
  session->trace_frame = trace_frame;
  session->replay_step = replay_step;
  session->trace_frame_reached = trace_frame_reached;
  session->environment_bug_detector = environment_bug_detector;
  memcpy(session->syscallbuf_flush_buffer_array, syscallbuf_flush_buffer_array,
         sizeof(syscallbuf_flush_buffer_array));

  for (auto vm : sas) {
    // Creating a checkpoint of a session with active breakpoints
    // or watchpoints is not supported.
    assert(!vm->has_breakpoints());
    assert(!vm->has_watchpoints());

    Task* some_task = *vm->task_set().begin();
    pid_t tgid = some_task->tgid();
    Task* group_leader = find_task(tgid);
    LOG(debug) << "  forking tg " << tgid
               << " (real: " << group_leader->real_tgid() << ")";

    if (group_leader->is_probably_replaying_syscall()) {
      group_leader->finish_emulated_syscall();
    }

    Task* clone_leader = group_leader->os_fork_into(session.get());
    session->track(clone_leader);
    LOG(debug) << "  forked new group leader " << clone_leader->tid;

    {
      AutoRemoteSyscalls remote(clone_leader);
      for (auto& kv : clone_leader->vm()->memmap()) {
        const Mapping& m = kv.first;
        const MappableResource& r = kv.second;
        if (!r.is_shared_mmap_file()) {
          continue;
        }
        remap_shared_mmap(remote, *session, m, r);
      }

      for (auto t : group_leader->task_group()->task_set()) {
        if (group_leader == t) {
          continue;
        }
        LOG(debug) << "    cloning " << t->rec_tid;

        if (t->is_probably_replaying_syscall()) {
          t->finish_emulated_syscall();
        }
        Task* t_clone = t->os_clone_into(clone_leader, remote);
        session->track(t_clone);
        t_clone->copy_state(t);
      }
    }
    LOG(debug) << "  restoring group-leader state ...";
    clone_leader->copy_state(group_leader);
  }
  assert(session->vms().size() > 0);

  return session;
}

ReplaySession::shr_ptr ReplaySession::clone_diversion() {
  auto session = clone();
  session->is_diversion = true;
  session->diversion_ref();
  LOG(debug) << "Cloned experiment session " << session.get();
  return session;
}

Task* ReplaySession::create_task(const struct args_env& ae, shr_ptr self,
                                 pid_t rec_tid) {
  assert(self.get() == this);
  Task* t = Task::spawn(ae, *this, rec_tid);
  track(t);
  return t;
}

void ReplaySession::gc_emufs() { emu_fs->gc(*this); }

/*static*/ ReplaySession::shr_ptr ReplaySession::create(int argc,
                                                        char* argv[]) {
  shr_ptr session(new ReplaySession());
  session->emu_fs = EmuFs::create();
  session->trace_ifstream = TraceIfstream::open(argc, argv);
  return session;
}
