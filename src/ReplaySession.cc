/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

//#define DEBUGTAG "ReplaySession"

#include "ReplaySession.h"

#include <syscall.h>
#include <sys/prctl.h>

#include <algorithm>

#include "AutoRemoteSyscalls.h"
#include "log.h"
#include "task.h"
#include "util.h"

using namespace rr;
using namespace std;

static void remap_shared_mmap(AutoRemoteSyscalls& remote,
                              ReplaySession& session, const Mapping& m,
                              const MappableResource& r) {
  LOG(debug) << "    remapping shared region at " << m.start << "-" << m.end;
  remote.syscall(syscall_number_for_munmap(remote.arch()), m.start,
                 m.num_bytes());
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
    remote_fd = remote.syscall(syscall_number_for_open(remote.arch()),
                               child_path.get().as_int(), oflags);
    if (0 > remote_fd) {
      FATAL() << "Couldn't open " << path << " in tracee";
    }
  }
  // XXX this condition is x86/x64-specific, I imagine.
  bool page_offset_mmap_in_use = has_mmap2_syscall(remote.arch());
  remote_ptr<void> addr = remote.syscall(
      page_offset_mmap_in_use ? syscall_number_for_mmap2(remote.arch())
                              : syscall_number_for_mmap(remote.arch()),
      m.start, m.num_bytes(), m.prot,
      // The remapped segment *must* be
      // remapped at the same address,
      // or else many things will go
      // haywire.
      m.flags | MAP_FIXED, remote_fd,
      page_offset_mmap_in_use ? m.offset / page_size() : m.offset);
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

  shr_ptr session(new ReplaySession(*this));
  LOG(debug) << "  deepfork session is " << session.get();
  session->tracees_consistent = tracees_consistent;
  session->emu_fs = emu_fs->clone();
  assert(!last_debugged_task);
  session->tgid_debugged = tgid_debugged;
  session->trace_frame = trace_frame;
  session->replay_step = replay_step;
  session->trace_frame_reached = trace_frame_reached;
  session->cpuid_bug_detector = cpuid_bug_detector;
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

Task* ReplaySession::create_task(pid_t rec_tid) {
  Task* t = Task::spawn(*this, rec_tid);
  track(t);
  return t;
}

void ReplaySession::gc_emufs() { emu_fs->gc(*this); }

/*static*/ ReplaySession::shr_ptr ReplaySession::create(int argc,
                                                        char* argv[]) {
  shr_ptr session(new ReplaySession(argc > 0 ? argv[0] : ""));
  session->emu_fs = EmuFs::create();
  return session;
}
