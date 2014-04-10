/* -*- Mode: C++; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

//#define DEBUGTAG "ProcessSyscallRep"

#include "replay_syscall.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <linux/if.h>
#include <linux/net.h>
#include <linux/mman.h>
#include <linux/prctl.h>
#include <linux/shm.h>
#include <linux/sem.h>
#include <linux/sockios.h>
#include <linux/soundcard.h>
#include <linux/wireless.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syscall.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/quota.h>
#include <sys/socket.h>
#include <sys/sysctl.h>

#include <map>
#include <memory>
#include <sstream>
#include <string>

#include <rr/rr.h>

#include "preload/syscall_buffer.h"

#include "dbg.h"
#include "replayer.h"
#include "task.h"
#include "trace.h"
#include "util.h"

using namespace std;

enum SyscallDefType {
	rep_UNDEFINED,	/* NB: this symbol must have the value 0 */
	rep_EMU,
	rep_EXEC,
	rep_EXEC_RET_EMU,
	rep_IRREGULAR
};
struct syscall_def {
	int no;
	/* See syscall_defs.h for documentation on these values. */
        SyscallDefType type;
	/* Not meaningful for rep_IRREGULAR. */
	ssize_t num_emu_args;
};

#define SYSCALL_NUM(_name)__NR_##_name
#define SYSCALL_DEF(_type, _name, _num_args)		\
	{ SYSCALL_NUM(_name), rep_##_type, _num_args },

static struct syscall_def syscall_defs[] = {
	/* Not-yet-defined syscalls will end up being type
	 * rep_UNDEFINED. */
#include "syscall_defs.h"
};
#undef SYSCALL_DEF
#undef SYSCALL_NUM

static struct syscall_def syscall_table[MAX_NR_SYSCALLS];

__attribute__((constructor))
static void init_syscall_table()
{
	static_assert(ALEN(syscall_defs) <= MAX_NR_SYSCALLS, "");
	for (size_t i = 0; i < ALEN(syscall_defs); ++i) {
		const struct syscall_def& def = syscall_defs[i];
		assert(def.no < MAX_NR_SYSCALLS);
		syscall_table[def.no] = def;
	}
}

static void replace_char(string& s, char c, char replacement)
{
	size_t i;
	while (string::npos != (i = s.find(c))) {
		s[i] = replacement;
	}
}

/**
 * Implement an "emulated file system" consisting of files that were
 * mmap'd shared during recording.  These files require special
 * treatment because (i) they were most likely modified during
 * recording, so (ii) the original file contents only exist as
 * snapshots in the trace, but (iii) all mappings of the file must
 * point at the same underling resource, so that modifications are
 * seen by all mappees.
 *
 * The rr EmuFs creates "emulated files" in shared memory during
 * replay.  Each efile is uniquely identified at a given event in the
 * trace by |(edev, einode)| (i.e., the recorded device ID and inode).
 * "What about inode recycling", you're probably thinking to yourself.
 * This scheme can cope with inode recycling, given a very important
 * assumption discussed below.
 *
 * Why is inode recycling not a problem?  Assume that an mmap'd file
 * F_0 at trace time t_0 has the same (device, inode) ID as a
 * different file F_1 at trace time t_1.  By definition, if the inode
 * ID was recycled in [t_0, t_1), then all references to F_0 must have
 * been dropped in that inverval.  A corollary of that is that all
 * memory mappings of F_0 must have been fully unmapped in the
 * interval.  As per the first long comment in |gc()| below, an
 * emulated file can only be "live" during replay if some tracee still
 * has a mapping of it.  Tracees' mappings of emulated files is a
 * subset of the ways they can create references to real files during
 * recording.  Therefore the event during replay that drops the last
 * reference to the emulated F_0 must be a tracee unmapping of F_0.
 *
 * So as long as we GC emulated F_0 at the event of its fatal
 * unmapping, the lifetimes of emulated F_0 and emulated F_1 must be
 * disjoint.  And F_0 being GC'd at that point is the important
 * assumption mentioned above.
 */
namespace EmuFs {

struct File {
	typedef shared_ptr<File> shr_ptr;

	~File() { debug("    EmuFs::~File(einode:%ld)", est.st_ino); }

	/**
	 * Ensure that the emulated file is sized to match a later
	 * stat() of it, |st|.
	 */
	void update(const struct stat& st) {
		assert(est.st_dev == st.st_dev && est.st_ino == st.st_ino);
		if (est.st_size != st.st_size) {
			resize_shmem_segment(fd, st.st_size);
		}
		est = st;
	}

	/**
	 * Create a new emulated file for |orig_path| that will
	 * emulate the recorded attributes |est|.
	 */
	static shr_ptr create(const char* orig_path, const struct stat& est) {
		// Sanitize the mapped file path so that we can use it
		// in a leaf name.
		string tag(orig_path);
		replace_char(tag, '/', '\\');

		stringstream name;
		name << "rr-emufs-dev-" << est.st_dev
		     << "-inode-" << est.st_ino
		     << "-" << tag;
		shr_ptr f(new File(create_shmem_segment(name.str().c_str(),
							est.st_size),
				   est));
		debug("created emulated file for %s as %s",
		      orig_path, name.str().c_str());
		return f;
	}

	struct stat est;
	ScopedOpen fd;
	bool marked;

private:
	File(int fd, const struct stat& est)
		: est(est), fd(fd), marked(false) { }

	File(const File&) = delete;
	File operator=(const File&) = delete;
};

typedef map<FileId, File::shr_ptr> FileMap;
static FileMap emufs;

static void mark_used_vfiles(Task* t, const AddressSpace& as,
			     size_t* nr_marked_files)
{
	for (auto it = as.begin(); it != as.end(); ++it) {
		const MappableResource& r = it->second;
		debug("  examining %s ...", r.fsname.c_str());

		auto id_ef = emufs.find(r.id);
		if (id_ef == emufs.end()) {
			continue;
		}
		auto ef = id_ef->second;
		if (!ef->marked) {
			ef->marked = true;
			debug("    marked einode:%ld", r.id.inode);
			++*nr_marked_files;
			if (emufs.size() == *nr_marked_files) {
				debug("  (marked all files, bailing)");
				return;
			}
		}
	}
}

void gc()
{
	// XXX this implementation is unnecessarily slow.  But before
	// throwing it away for something different, give it another
	// shot once rr is caching local mmaps for all address spaces,
	// which obviates the need for the yuck slow maps parsing
	// here.
	debug("Beginning emufs gc of %d files", emufs.size());

	// Mark in-use files by iterating through the mmaps of all
	// tracee address spaces.
	//
	// We inject these maps into the tracee and are careful to
	// close the injected fd after we finish the mmap.  That means
	// that the only way tracees can hold a reference to the
	// underlying inode is through a memory mapping.  So to
	// determine if a file is in use, we only have to find a
	// recognizable filename in some tracee's memory map.
	//
	// We check *all* tracee file tables because tracees can share
	// fds with each other in many ways, and we don't attempt to
	// track any of that.
	//
	// TODO: assuming AddressSpace == FileTable, but technically
	// they're different things: two tracees could share an
	// address space but have different file tables.
	size_t nr_marked_files = 0;
	auto sas = AddressSpace::set();
	for (auto it = sas.begin(); it != sas.end(); ++it) {
		AddressSpace* as = *it;
		Task* t = *as->task_set().begin();
		debug("  iterating /proc/%d/maps ...", t->tid);

		mark_used_vfiles(t, *as, &nr_marked_files);
		if (emufs.size() == nr_marked_files) {
			break;
		}
	}

	// Sweep all the virtual files that weren't marked.  It might
	// be possible that a later task will mmap the same underlying
	// file that we're about to destroy.  That's perfectly fine;
	// we'll just create it anew, and restore its addressible
	// contents from the snapshot saved to the trace.  Since there
	// are no live references to the file in the interim, tracees
	// can't observe the destroy/recreate operation.
	vector<FileId> garbage;
	for (auto it = emufs.begin(); it != emufs.end(); ++it) {
		if (!it->second->marked) {
			garbage.push_back(it->first);
		}
		it->second->marked = false;
	}
	for (auto it = garbage.begin(); it != garbage.end(); ++it) {
		debug("  emufs gc reclaiming einode:%ld", it->inode);
		emufs.erase(*it);
	}
}

AutoGc::AutoGc(int syscallno, int state)
	: is_gc_point(emufs.size() > 0
		      && STATE_SYSCALL_EXIT == state
		      && (SYS_close == syscallno
			  || SYS_munmap == syscallno)) {
	if (is_gc_point) {
		debug("emufs gc required because of syscall `%s'",
		      syscallname(syscallno));
	}
}

AutoGc::~AutoGc() {
	if (is_gc_point) {
		gc();
	}
}

/**
 * Return an fd that refers to an emulated file representing the
 * recorded file underlying |mf|.
 */
static int get_or_create(const struct mmapped_file& mf)
{
	auto it = emufs.find(mf.stat);
	if (it != emufs.end()) {
		it->second->update(mf.stat);
		return it->second->fd;
	}
	auto vf = File::create(mf.filename, mf.stat);
	emufs[mf.stat] = vf;
	return vf->fd;
}

} // namepsace Emufs

extern bool validate;

/**
 * Compares the register file as it appeared in the recording phase
 * with the current register file.
 */
static void validate_args(int syscall, int state, Task* t)
{
	/* don't validate anything before execve is done as the actual
	 * process did not start prior to this point */
	if (!validate) {
		return;
	}
	assert_child_regs_are(t, &t->trace.recorded_regs);
}

/**
 * Proceeds until the next system call, which is not executed.
 */
static void goto_next_syscall_emu(Task *t)
{
	t->cont_sysemu();

	int sig = t->pending_sig();
	/* SIGCHLD is pending, do not deliver it, wait for it to
	 * appear in the trace SIGCHLD is the only signal that should
	 * ever be generated as all other signals are emulated! */
	if (sig == SIGCHLD) {
		goto_next_syscall_emu(t);
		return;
	} else if (SIGTRAP == sig) {
		fatal("SIGTRAP while entering syscall ... were you using a debugger? If so, the current syscall needs to be made interruptible");
	} else if (sig) {
		fatal("Replay got unrecorded signal %d", sig);
	}

	/* check if we are synchronized with the trace -- should never
	 * fail */
	const int rec_syscall = t->trace.recorded_regs.orig_eax;
	const int current_syscall = t->regs().orig_eax;

	if (current_syscall != rec_syscall) {
		/* this signal is ignored and most likey delivered
		 * later, or was already delivered earlier */
		/* TODO: this code is now obselete */
		if (t->stop_sig() == SIGCHLD) {
			debug("do we come here?\n");
			/*t->replay_sig = SIGCHLD; // remove that if
			 * spec does not work anymore */
			goto_next_syscall_emu(t);
			return;
		}

		assert_exec(t, current_syscall == rec_syscall,
			    "Should be at `%s', instead at `%s'",
			    syscallname(rec_syscall),
			    syscallname(current_syscall));
	}
	t->child_sig = 0;
}

/**
 *  Step over the system call to be able to reuse PTRACE_SYSTEM call
 */
static void finish_syscall_emu(Task *t)
{
	struct user_regs_struct r = t->regs();
	t->cont_sysemu_singlestep();
	t->set_regs(r);

	t->force_status(0);
}

/**
 * Proceeds until the next system call, which is being executed.
 */
void __ptrace_cont(Task *t)
{
	t->cont_syscall();

	t->child_sig = t->pending_sig();

	/* check if we are synchronized with the trace -- should never fail */
	int rec_syscall = t->trace.recorded_regs.orig_eax;
	int current_syscall = t->regs().orig_eax;
	if (current_syscall != rec_syscall && t->stop_sig() == SIGCHLD) {
		/* SIGCHLD can be delivered pretty much at any time
		 * during replay, and we need to ignore it since
		 * replayed signals are only emulated. */
		__ptrace_cont(t);
		t->child_sig = 0;
		return;
	}
	assert_exec(t, current_syscall == rec_syscall,
		    "Should be at %s, but instead at %s\n",
		    syscallname(rec_syscall), syscallname(current_syscall));
}

void rep_maybe_replay_stdio_write(Task* t)
{
	int fd;

	if (!rr_flags()->redirect) {
		return;
	}

	assert(SYS_write == t->regs().orig_eax
	       || SYS_writev == t->regs().orig_eax);

	fd = t->regs().ebx;
	if (fd == STDOUT_FILENO || fd == STDERR_FILENO) {
		ssize_t len = t->regs().edx;
		void* addr = (void*) t->regs().ecx;
		byte buf[len];
		// NB: |buf| may not be null-terminated.
		t->read_bytes_helper(addr, sizeof(buf), buf);
		maybe_mark_stdio_write(t, fd);
		if (len != write(fd, buf, len)) {
			fatal("Couldn't write stdio");
		}
	}
}

static void exit_syscall_emu_ret(Task* t, int syscall)
{
	t->set_return_value_from_trace();
	validate_args(syscall, STATE_SYSCALL_EXIT, t);
	finish_syscall_emu(t);
}

static void exit_syscall_emu(Task* t,
			     int syscall, int num_emu_args)
{
	int i;

	for (i = 0; i < num_emu_args; ++i) {
		t->set_data_from_trace();
	}
	exit_syscall_emu_ret(t, syscall);
}

static void init_scratch_memory(Task* t)
{
	/* Initialize the scratchpad as the recorder did, but make it
	 * PROT_NONE. The idea is just to reserve the address space so
	 * the replayed process address map looks like the recorded
	 * process, if it were to be probed by madvise or some other
	 * means. But we make it PROT_NONE so that rogue reads/writes
	 * to the scratch memory are caught. */
	struct mmapped_file file;
	struct current_state_buffer state;
	void* map_addr;

	read_next_mmapped_file_stats(&file);

	prepare_remote_syscalls(t, &state);

	t->scratch_ptr = file.start;
	t->scratch_size = (byte*)file.end - (byte*)file.start;

	size_t sz = t->scratch_size;
	int prot = PROT_NONE;
	int flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED;
	int fd = -1;
	off_t offset = 0;

	map_addr = (void*)remote_syscall6(
		t, &state, SYS_mmap2,
		t->scratch_ptr, sz, prot, flags, fd, offset);
	finish_remote_syscalls(t, &state);

	assert_exec(t, t->scratch_ptr == map_addr,
		    "scratch mapped %p during recording, but %p in replay",
		    file.start, map_addr);

	t->vm()->map(map_addr, sz, prot, flags, offset,
		     MappableResource::scratch(t->rec_tid));
}

/**
 * If scratch data was incidentally recorded for the current desched'd
 * but write-only syscall, then do a no-op restore of that saved data
 * to keep the trace in sync.
 *
 * Syscalls like |write()| that may-block and are wrapped in the
 * preload library can be desched'd.  When this happens, we save the
 * syscall record's "extra data" as if it were normal scratch space,
 * since it's used that way in effect.  But syscalls like |write()|
 * that don't actually use scratch space don't ever try to restore
 * saved scratch memory during replay.  So, this helper can be used
 * for that class of syscalls.
 */
static void maybe_noop_restore_syscallbuf_scratch(Task* t)
{
	if (t->is_untraced_syscall()) {
		debug("  noop-restoring scratch for write-only desched'd %s",
		      syscallname(t->regs().orig_eax));
		t->set_data_from_trace();
	}
}

/**
 * Return true iff the syscall represented by |frame| (either entry to
 * or exit from) failed.
 */
static bool is_failed_syscall(const struct trace_frame* frame)
{
	struct trace_frame next_frame;
	if (STATE_SYSCALL_ENTRY == frame->ev.state) {
		peek_next_trace(&next_frame);
		frame = &next_frame;
	}
	return SYSCALL_FAILED(frame->recorded_regs.eax);
}

static void process_clone(Task* t,
			  struct trace_frame* trace, int state,
			  struct rep_trace_step* step)
{
	int syscallno = SYS_clone;
	if (is_failed_syscall(trace)) {
		/* creation failed, emulate it */
		step->syscall.emu = 1;
		step->syscall.emu_ret = 1;
		step->action = (state == STATE_SYSCALL_ENTRY) ?
			       TSTEP_ENTER_SYSCALL : TSTEP_EXIT_SYSCALL;
		return;
	}
	if (state == STATE_SYSCALL_ENTRY) {
		step->action = TSTEP_ENTER_SYSCALL;
		return;
	}

	struct user_regs_struct rec_regs = trace->recorded_regs;
	unsigned long flags = rec_regs.ebx;

	if (flags & CLONE_UNTRACED) {
		// See related comment in rec_process_event.c.
		rec_regs.ebx = flags & ~CLONE_UNTRACED;
		t->set_regs(rec_regs);
	}

	// TODO: can debugger signals interrupt us here?

	/* execute the system call */
	__ptrace_cont(t);
	/* wait for the signal that a new process is created */
	__ptrace_cont(t);

	int rec_tid = rec_regs.eax;
	pid_t new_tid = t->get_ptrace_eventmsg();

	void* stack = (void*)t->regs().ecx;
	void* ctid = (void*)t->regs().edi;
	int flags_arg = (SYS_clone == t->regs().orig_eax) ? t->regs().ebx : 0;

	Task* new_task = t->clone(clone_flags_to_task_flags(flags_arg),
				  stack, ctid, new_tid, rec_tid);
	// Wait until the new thread is ready.
	new_task->wait();

	/* FIXME: what if registers are non-null and contain an
	 * invalid address? */
	t->set_data_from_trace();
	t->set_data_from_trace();

	new_task->trace = t->trace;
	new_task->set_data_from_trace();
	new_task->set_data_from_trace();
	new_task->set_data_from_trace();
	if (!(CLONE_VM & flags)) {
		// It's hard to imagine a scenario in which it would
		// be useful to inherit breakpoints (along with their
		// refcounts) across a non-VM-sharing clone, but for
		// now we never want to do this.
		new_task->vm()->destroy_all_breakpoints();
	}

	struct user_regs_struct r = t->regs();
	/* set the ebp register to the recorded value -- it should not
	 * point to data on that is used afterwards */
	r.ebp = rec_regs.ebp;
	// Restore the saved flags, to hide the fact that we may have
	// masked out CLONE_UNTRACED.
	r.ebx = flags;
	t->set_regs(r);
	t->set_return_value_from_trace();
	validate_args(syscallno, state, t);

	init_scratch_memory(new_task);

	step->action = TSTEP_RETIRE;
}

static void process_execve(Task* t, struct trace_frame* trace, int state,
			   const struct user_regs_struct* rec_regs,
			   struct rep_trace_step* step)
{
	const int syscallno = SYS_execve;

	if (is_failed_syscall(trace)) {
		/* exec failed, emulate it */
		step->syscall.emu = 1;
		step->syscall.emu_ret = 1;
		step->action = (state == STATE_SYSCALL_ENTRY) ?
			       TSTEP_ENTER_SYSCALL : TSTEP_EXIT_SYSCALL;
		return;
	}

	if (STATE_SYSCALL_ENTRY == state) {
		// Executed, not emulated.
		step->action = TSTEP_ENTER_SYSCALL;
		return;
	}

	step->action = TSTEP_RETIRE;

	/* we need an additional ptrace syscall, since ptrace is setup
	 * with PTRACE_O_TRACEEXEC */
	__ptrace_cont(t);

	/* We just saw a successful exec(), so from now on we know
	 * that the address space layout for the replay tasks will
	 * (should!) be the same as for the recorded tasks.  So we can
	 * start validating registers at events. */
	validate = true;

	bool check = t->regs().ebx;
	/* if the execve comes from a vfork system call the ebx
	 * register is not zero. in this case, no recorded data needs
	 * to be injected */
	if (check == 0) {
		t->set_data_from_trace();
	}

	init_scratch_memory(t);

	t->post_exec();

	t->set_return_value_from_trace();
	validate_args(syscallno, state, t);
}

static void process_futex(Task* t, int state, struct rep_trace_step* step,
			  const struct user_regs_struct* regs)
{
	int op = regs->ecx & FUTEX_CMD_MASK;
	void* futex = (void*)regs->ebx;

	step->syscall.emu = 1;
	step->syscall.emu_ret = 1;

	if (state == STATE_SYSCALL_ENTRY) {
		if (FUTEX_LOCK_PI == op) {
			uint32_t next_val;
			if (is_now_contended_pi_futex(t, futex, &next_val)) {
				static_assert(sizeof(next_val) == sizeof(long),
					      "Sorry, need Task::write_int()");
				// During recording, we waited for the
				// kernel to update the futex, but
				// since we emulate SYS_futex in
				// replay, we need to set it ourselves
				// here.
				t->write_mem(futex, next_val);
			}
		}
		step->action = TSTEP_ENTER_SYSCALL;
		return;
	}

	step->action = TSTEP_EXIT_SYSCALL;
	switch (op) {
	case FUTEX_LOCK_PI:
	case FUTEX_WAKE:
	case FUTEX_WAIT_BITSET:
	case FUTEX_WAIT:
	case FUTEX_UNLOCK_PI:
		step->syscall.num_emu_args = 1;
		return;
	case FUTEX_CMP_REQUEUE:
	case FUTEX_WAKE_OP:
	case FUTEX_CMP_REQUEUE_PI:
	case FUTEX_WAIT_REQUEUE_PI:
		step->syscall.num_emu_args = 2;
		return;
	default:
		fatal("Unknown futex op %d", op);
	}
}

static void process_ioctl(Task* t, int state, struct rep_trace_step* step)
{
	int request;
	int dir;

	step->syscall.emu = 1;
	step->syscall.emu_ret = 1;

	if (state == STATE_SYSCALL_ENTRY) {
		step->action = TSTEP_ENTER_SYSCALL;
		return;
	}

	step->action = TSTEP_EXIT_SYSCALL;
	request = t->regs().ecx;
	dir = _IOC_DIR(request);

	debug("Processing ioctl 0x%x: dir 0x%x", request, dir);

	/* Process special-cased ioctls first. */
	switch (request) {
	case SIOCGIFCONF:
		step->syscall.num_emu_args = 3;
		return;

	case SIOCETHTOOL:
	case SIOCGIFADDR:
	case SIOCGIFFLAGS:
	case SIOCGIFINDEX:
	case SIOCGIFMTU:
	case SIOCGIFNAME:
	case SIOCGIWRATE:
		step->syscall.num_emu_args = 2;
		return;

	case TCGETS:
	case TIOCINQ:
	case TIOCGWINSZ:
		step->syscall.num_emu_args = 1;
		return;
	}
	/* Now on to the "regular" ioctls. */

	if (!(_IOC_WRITE & dir)) {
		/* Deterministic ioctl(), no data to restore to the
		 * tracee. */
		return;
	}

	switch (request) {
	default:
		fatal("Unknown ioctl 0x%x", request);
	}
}

void process_ipc(Task* t, struct trace_frame* trace, int state,
		 struct rep_trace_step* step)
{
	step->syscall.emu = 1;
	step->syscall.emu_ret = 1;
	if (STATE_SYSCALL_ENTRY == state) {
		step->action = TSTEP_ENTER_SYSCALL;
		return;
	}

	step->action = TSTEP_EXIT_SYSCALL;
	int call = trace->recorded_regs.ebx;
	debug("ipc call: %d\n", call);
	switch (call) {
	case MSGCTL:
	case MSGRCV:
		step->syscall.num_emu_args = 1;
		return;
	default:
		step->syscall.num_emu_args = 0;
		return;
	}
}

/**
 * Pass NOTE_TASK_MAP to update |t|'s cached mmap data.  If the data
 * need to be manually updated, pass |DONT_NOTE_TASK_MAP| and update
 * it manually.
 */
enum { DONT_NOTE_TASK_MAP = 0, NOTE_TASK_MAP };

static void* finish_anonymous_mmap(Task* t,
				   struct current_state_buffer* state,
				   struct trace_frame* trace,
				   int prot, int flags,
				   off64_t offset_pages,
				   int note_task_map=NOTE_TASK_MAP)
{
	const struct user_regs_struct* rec_regs = &trace->recorded_regs;
	/* *Must* map the segment at the recorded address, regardless
	   of what the recorded tracee passed as the |addr| hint. */
	void* rec_addr = (void*)rec_regs->eax;
	size_t length = rec_regs->ecx;
	/* These are supposed to be (-1, 0) respectively, but use
	 * whatever the tracee passed to avoid stirring up trouble. */
	int fd = rec_regs->edi;

	if (note_task_map) {
		t->vm()->map(rec_addr, length, prot, flags,
			     page_size() * offset_pages,
			     MappableResource::anonymous());
	}

	return (void*)remote_syscall6(t, state, SYS_mmap2,
				      rec_addr, length, prot,
				      /* Tell the kernel to take
				       * |rec_addr| seriously. */
				      flags | MAP_FIXED,
				      fd, offset_pages);
}

/* Ensure that accesses to the memory region given by start/length
   cause a SIGBUS, as for accesses beyond the end of an mmaped file. */
static void create_sigbus_region(Task* t,
				 struct current_state_buffer* state,
				 int prot, void* start, size_t length)
{
	if (length == 0) {
		return;
	}

	/* Open an empty file in the tracee */
	char filename[] = PREFIX_FOR_EMPTY_MMAPED_REGIONS "XXXXXX";
	int fd = mkstemp(filename);
	/* Close our side immediately */
	close(fd);

	int child_fd;
	{
		struct restore_mem restore;
		void* child_str = push_tmp_str(t, state, filename, &restore);
		child_fd = remote_syscall2(t, state, SYS_open, child_str, O_RDONLY);
		if (0 > child_fd) {
			fatal("Couldn't open %s to mmap in tracee", filename);
		}
		pop_tmp_mem(t, state, &restore);
	}

	/* Unlink it now that the child has opened it */
	unlink(filename);

	/* mmap it in the tracee. We need to set the correct 'prot' flags
	   so that the correct signal is generated on a memory access
	   (SEGV if 'prot' doesn't allow the access, BUS if 'prot' does allow
	   the access). */
	remote_syscall6(t, state, SYS_mmap2,
			start, length,
			prot, MAP_FIXED | MAP_PRIVATE,
			child_fd, 0);
	/* Don't leak the tmp fd.  The mmap doesn't need the fd to
	 * stay open. */
	remote_syscall1(t, state, SYS_close, fd);
}

static void* finish_private_mmap(Task* t,
				 struct current_state_buffer* state,
				 struct trace_frame* trace,
				 int prot, int flags,
				 off64_t offset_pages,
				 const struct mmapped_file* file)
{
	debug("  finishing private mmap of %s", file->filename);

	const struct user_regs_struct& rec_regs = trace->recorded_regs;
	size_t num_bytes = rec_regs.ecx;
	void* mapped_addr = finish_anonymous_mmap(t, state, trace, prot,
						  /* The restored region
						   * won't be backed by
						   * file. */
						  flags | MAP_ANONYMOUS,
						  DONT_NOTE_TASK_MAP);
	/* Restore the map region we copied. */
	ssize_t data_size = t->set_data_from_trace();

	/* Ensure pages past the end of the file fault on access */
	size_t data_pages = ceil_page_size(data_size);
	size_t mapped_pages = ceil_page_size(num_bytes);
	create_sigbus_region(t, state, prot, (char*)mapped_addr + data_pages,
			     mapped_pages - data_pages);

	t->vm()->map(mapped_addr, num_bytes, prot, flags,
		     page_size() * offset_pages,
		     // Intentionally drop the stat() information
		     // saved to trace so as to match /proc/maps's
		     // device/inode info for this anonymous mapping.
		     // Preserve the mapping name though, so
		     // AddressSpace::dump() shows something useful.
		     MappableResource(FileId(), file->filename));

	return mapped_addr;
}

static void verify_backing_file(const struct mmapped_file* file,
				int prot, int flags)
{
	struct stat metadata;
	if (stat(file->filename, &metadata)) {
		fatal("Failed to stat %s: replay is impossible",
		      file->filename);
	}
	if (metadata.st_ino != file->stat.st_ino
	    || metadata.st_mode != file->stat.st_mode
	    || metadata.st_uid != file->stat.st_uid
	    || metadata.st_gid != file->stat.st_gid
	    || metadata.st_size != file->stat.st_size
	    || metadata.st_mtime != file->stat.st_mtime
	    || metadata.st_ctime != file->stat.st_ctime) {
		log_err("Metadata of %s changed: replay divergence likely, but continuing anyway ...",
			 file->filename);
	}
	if (should_copy_mmap_region(file->filename, &metadata, prot, flags,
				    WARN_DEFAULT)) {
		log_err("%s wasn't copied during recording, but now it should be?",
			file->filename);
	}

}

enum { DONT_VERIFY = 0, VERIFY_BACKING_FILE };
static void* finish_direct_mmap(Task* t,
				struct current_state_buffer* state,
				struct trace_frame* trace,
				int prot, int flags,
				off64_t offset_pages,
				const struct mmapped_file* file,
				int verify = VERIFY_BACKING_FILE,
				int note_task_map=NOTE_TASK_MAP)
{
	struct user_regs_struct* rec_regs = &trace->recorded_regs;
	void* rec_addr = (void*)rec_regs->eax;
	size_t length = rec_regs->ecx;
	int fd;
	void* mapped_addr;

	debug("directly mmap'ing %d bytes of %s at page offset 0x%llx",
	      length, file->filename, offset_pages);

	if (verify) {
		verify_backing_file(file, prot, flags);
	}

	/* Open in the tracee the file that was mapped during
	 * recording. */
	{
		struct restore_mem restore;
		void* child_str = push_tmp_str(t, state, file->filename,
					       &restore);
		/* We only need RDWR for shared writeable mappings.
		 * Private mappings will happily COW from the mapped
		 * RDONLY file.
		 *
		 * TODO: should never map any files writable */
		int oflags = (MAP_SHARED & flags) && (PROT_WRITE & prot) ?
			     O_RDWR : O_RDONLY;
		/* TODO: unclear if O_NOATIME is relevant for mmaps */
		fd = remote_syscall2(t, state, SYS_open, child_str, oflags);
		if (0 > fd) {
			fatal("Couldn't open %s to mmap in tracee",
			      file->filename);
		}
		pop_tmp_mem(t, state, &restore);
	}
	/* And mmap that file. */
	mapped_addr = (void*)
		      remote_syscall6(t, state, SYS_mmap2,
				      rec_addr, length,
				      /* (We let SHARED|WRITEABLE
				       * mappings go through while
				       * they're not handled properly,
				       * but we shouldn't do that.) */
				      prot, flags,
				      fd, offset_pages);
	/* Don't leak the tmp fd.  The mmap doesn't need the fd to
	 * stay open. */
	remote_syscall1(t, state, SYS_close, fd);

	if (note_task_map) {
		t->vm()->map(mapped_addr, length, prot, flags,
			     page_size() * offset_pages,
			     MappableResource(FileId(file->stat),
					      file->filename));
	}

	return mapped_addr;
}

static void* finish_shared_mmap(Task* t,
				struct current_state_buffer* state,
				struct trace_frame* trace,
				int prot, int flags,
				off64_t offset_pages,
				const struct mmapped_file* file)
{
	const struct user_regs_struct& rec_regs = trace->recorded_regs;
	size_t rec_num_bytes = ceil_page_size(rec_regs.ecx);

	// Ensure there's a virtual file for the file that was mapped
	// during recording.
	int emufs_fd = EmuFs::get_or_create(*file);
	// Re-use the direct_map() machinery to map the virtual file.
	//
	// NB: the tracee will map the procfs link to our fd; there's
	// no "real" name for the file anywhere, to ensure that when
	// we exit/crash the kernel will clean up for us.
	struct mmapped_file vfile = *file;
	snprintf(vfile.filename, sizeof(vfile.filename) - 1,
		 "/proc/%d/fd/%d", getpid(), emufs_fd);
	void* mapped_addr = finish_direct_mmap(t, state, trace, prot, flags,
					       offset_pages,
					       &vfile, DONT_VERIFY,
					       DONT_NOTE_TASK_MAP);
	// Write back the snapshot of the segment that we recorded.
	// We have to write directly to the underlying file, because
	// the tracee may have mapped its segment read-only.
	// 
	// TODO: this is a poor man's shared segment synchronization.
	// For full generality, we also need to emulate direct file
	// modifications through write/splice/etc.
	void* rec_addr;
	size_t num_bytes;
	byte* data = (byte*)read_raw_data(&(t->trace), &num_bytes, &rec_addr);
	assert(data && rec_addr == mapped_addr &&
	       rec_num_bytes == ceil_page_size(num_bytes));

	off64_t offset_bytes = page_size() * offset_pages;
	if (ssize_t(num_bytes) !=
	    pwrite64(emufs_fd, data, num_bytes, offset_bytes)) {
		fatal("Failed to write %d bytes at %#llx to %s",
		      num_bytes, offset_bytes, vfile.filename);
	}
	free(data);
	debug("  restored %d bytes at 0x%llx to %s",
	      num_bytes, offset_bytes, vfile.filename);

	t->vm()->map(mapped_addr, num_bytes, prot, flags,
		     offset_bytes,
		     MappableResource(FileId(file->stat), file->filename));

	return mapped_addr;
}

static void process_mmap2(Task* t,
			  struct trace_frame* trace, int exec_state,
			  struct rep_trace_step* step)
{
	int prot = trace->recorded_regs.edx;
	int flags = trace->recorded_regs.esi;
	off64_t offset_pages = trace->recorded_regs.ebp;
	struct current_state_buffer state;
	void* mapped_addr;

	if (STATE_SYSCALL_ENTRY == exec_state) {
		/* We emulate entry for all types of mmap calls,
		 * successful and not. */
		step->action = TSTEP_ENTER_SYSCALL;
		step->syscall.emu = 1;
		return;
	}
	if (SYSCALL_FAILED(trace->recorded_regs.eax)) {
		/* Failed maps are fully emulated too; nothing
		 * interesting to do. */
		step->action = TSTEP_EXIT_SYSCALL;
		step->syscall.emu = 1;
		step->syscall.emu_ret = 1;
		return;
	}
	/* Successful mmap calls are much more interesting to process.
	 * First we advance to the emulated syscall exit. */
	finish_syscall_emu(t);
	/* Next we hand off actual execution of the mapping to the
	 * appropriate helper. */
	prepare_remote_syscalls(t, &state);
	if (flags & MAP_ANONYMOUS) {
		mapped_addr = finish_anonymous_mmap(t, &state, trace,
						    prot, flags, offset_pages);
	} else {
		struct mmapped_file file;
		read_next_mmapped_file_stats(&file);

		assert_exec(t, file.time == trace->global_time,
			    "mmap time %u should equal %u",
			    file.time, trace->global_time);
		if (!file.copied) {
			mapped_addr = finish_direct_mmap(t, &state, trace,
							 prot, flags,
							 offset_pages, &file);
		} else if (!(MAP_SHARED & flags)) {
			mapped_addr = finish_private_mmap(t, &state, trace,
							  prot, flags,
							  offset_pages, &file);
		} else {
			mapped_addr = finish_shared_mmap(t, &state, trace,
							 prot, flags,
							 offset_pages, &file);
		}
	}
	/* Finally, we finish by emulating the return value. */
	state.regs.eax = (uintptr_t)mapped_addr;
	finish_remote_syscalls(t, &state);

	validate_args(SYS_mmap2, exec_state, t);

	step->action = TSTEP_RETIRE;
}

/**
 * Return nonzero if this socketcall was "regular" and |step| was
 * updated appropriately, or zero if this was an irregular socketcall
 * that needs to be processed specially.
 */
static void process_socketcall(Task* t, int state,
			       struct rep_trace_step* step)
{
	int call;

	step->syscall.emu = 1;
	step->syscall.emu_ret = 1;

	if (state == STATE_SYSCALL_ENTRY) {
		step->action = TSTEP_ENTER_SYSCALL;
		return;
	}

	step->action = TSTEP_EXIT_SYSCALL;
	switch ((call = t->regs().ebx)) {
		/* FIXME: define a SSOT for socketcall record and
		 * replay data, a la syscall_defs.h */
	case SYS_SOCKET:
	case SYS_CONNECT:
	case SYS_BIND:
	case SYS_LISTEN:
	case SYS_SENDMSG:
	case SYS_SEND:
	case SYS_SENDTO:
	case SYS_SETSOCKOPT:
	case SYS_SHUTDOWN:
		step->syscall.num_emu_args = 0;
		return;
	case SYS_GETPEERNAME:
	case SYS_GETSOCKNAME:
		step->syscall.num_emu_args = 2;
		return;
	case SYS_RECV:
		step->syscall.num_emu_args = 1;
		return;

	/* int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
	 * int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags);
	 *
	 * Note: The returned address is truncated if the buffer
	 * provided is too small; in this case, addrlen will return a
	 * value greater than was supplied to the call.
	 *
	 * For now we record the size of bytes that is returned by the
	 * system call. We check in the replayer, if the buffer was
	 * actually too small and throw an error there.
	 */
	case SYS_ACCEPT:
	case SYS_ACCEPT4:
		/* FIXME: not quite sure about socket_addr */
		step->syscall.num_emu_args = 2;
		return;

	case SYS_SOCKETPAIR:
		step->syscall.num_emu_args = 1;
		return;

	case SYS_GETSOCKOPT:
		step->syscall.num_emu_args = 2;
		return;

	case SYS_RECVFROM:
		step->syscall.num_emu_args = 3;
		return;

	case SYS_RECVMSG: {
		// We manually restore the msg buffer.
		step->syscall.num_emu_args = 0;

		void* base_addr = (void*)t->trace.recorded_regs.ecx;
		struct recvmsg_args args;
		t->read_mem(base_addr, &args);

		restore_struct_msghdr(t, args.msg);
		return;
	}
	default:
		fatal("Unhandled socketcall %d", call);
	}
}

static void process_init_buffers(Task* t, int exec_state,
				 struct rep_trace_step* step)
{
	void* rec_child_map_addr;
	void* child_map_addr;

	/* This was a phony syscall to begin with. */
	step->syscall.emu = 1;
	step->syscall.emu_ret = 1;

	if (STATE_SYSCALL_ENTRY == exec_state) {
		step->action = TSTEP_ENTER_SYSCALL;
		return;
	}

	step->action = TSTEP_RETIRE;

	/* Proceed to syscall exit so we can run our own syscalls. */
	finish_syscall_emu(t);
	rec_child_map_addr = (void*)t->trace.recorded_regs.eax;

	/* We don't want the desched event fd during replay, because
	 * we already know where they were.  (The perf_event fd is
	 * emulated anyway.) */
	child_map_addr = init_buffers(t, rec_child_map_addr,
				      DONT_SHARE_DESCHED_EVENT_FD);

	assert_exec(t, child_map_addr == rec_child_map_addr,
		    "Should have mapped syscallbuf at %p, but it's at %p",
		    rec_child_map_addr, child_map_addr);
	validate_args(SYS_rrcall_init_buffers, STATE_SYSCALL_EXIT, t);
}

static void process_restart_syscall(Task* t, int syscallno)
{
	switch (syscallno) {
	case SYS_nanosleep:
		/* Write the remaining-time outparam that we were
		 * forced to during recording. */
		t->set_data_from_trace();

	default:
		return;
	}
}

static void dump_path_data(Task* t, int global_time, const char* tag,
			   char* filename, size_t filename_size,
			   const void* buf, size_t buf_len, void* addr)
{
	format_dump_filename(t, global_time, tag, filename, filename_size);
	dump_binary_data(filename, tag,
			 (const uint32_t*)buf, buf_len / 4, addr);
}

static void
notify_save_data_error(Task* t, void* addr,
		       const void* rec_buf, size_t rec_buf_len,
		       const void* rep_buf, size_t rep_buf_len)
{
	char rec_dump[PATH_MAX];
	char rep_dump[PATH_MAX];
	int global_time = t->trace.global_time;

	dump_path_data(t, global_time, "rec_save_data",
		       rec_dump, sizeof(rec_dump), rec_buf, rec_buf_len, addr);
	dump_path_data(t, global_time,"rep_save_data",
		       rep_dump, sizeof(rep_dump), rep_buf, rep_buf_len, addr);

	assert_exec(t,
		    rec_buf_len == rep_buf_len && !memcmp(rec_buf, rep_buf,
							  rec_buf_len),
"Divergence in contents of 'tracee-save buffer'.  Recording executed\n"
"\n"
"  write(%d, %p, %u)\n"
"\n"
"and replay executed\n"
"\n"
"  write(%d, %p, %u)\n"
"\n"
"The contents of the tracee-save buffers have been dumped to disk.\n"
"Compare them by using the following command\n"
"\n"
"$ diff -u %s %s >save-data-diverge.diff\n"
		    , RR_MAGIC_SAVE_DATA_FD, addr, rec_buf_len,
		    RR_MAGIC_SAVE_DATA_FD, addr, rep_buf_len,
		    rec_dump, rep_dump);
}

/**
 * If the tracee saved data in this syscall to the magic save-data fd,
 * read and check the replay buffer against the one saved during
 * recording.
 */
static void maybe_verify_tracee_saved_data(Task* t,
					   const struct user_regs_struct* rec_regs)
{
	int fd = rec_regs->ebx;
	void* addr = (void*)rec_regs->ecx;
	size_t len = rec_regs->edx;
	void* rec_addr;
	size_t rec_len;
	void* rec_buf;

	if (RR_MAGIC_SAVE_DATA_FD != fd) {
		return;
	}

	rec_buf = read_raw_data(&t->trace, &rec_len, &rec_addr);
	/* If the data address changed, something disastrous happened
	 * and the buffers aren't comparable.  Just bail. */
	assert_exec(t, addr == rec_addr,
		    "Recorded write(%p) being replayed as write(%p)",
		    rec_addr, addr);

	byte buf[rec_len];
	t->read_bytes_helper(addr, len, buf);
	if (len != rec_len || memcmp(rec_buf, buf, len)) {
		notify_save_data_error(t, addr, rec_buf, rec_len, buf, len);
	}

	free(rec_buf);
}

void rep_after_enter_syscall(Task* t, int syscallno)
{
	if (SYS_write != syscallno) {
		return;
	}
	maybe_verify_tracee_saved_data(t, &t->trace.recorded_regs);
}

/**
 * Call this hook just before exiting a syscall.  Often Task
 * attributes need to be updated based on the finishing syscall.
 */
void before_syscall_exit(Task* t, int syscallno)
{
	switch (syscallno) {
	case SYS_sigaction:
		t->update_sigaction();
		return;

	case SYS_sigprocmask:
	case SYS_rt_sigprocmask:
		t->update_sigmask();
		return;

	default:
		return;
	}
}

void rep_process_syscall(Task* t, struct rep_trace_step* step)
{
	int syscall = t->trace.ev.data; /* FIXME: don't shadow syscall() */
	const struct syscall_def* def;
	struct trace_frame* trace = &(t->trace);
	int state = trace->ev.state;
	const struct user_regs_struct* rec_regs = &trace->recorded_regs;
	EmuFs::AutoGc maybe_gc(syscall, state);

	debug("processing %s (%s)", syscallname(syscall), statename(state));

	if (STATE_SYSCALL_EXIT == state
	    && SYSCALL_MAY_RESTART(rec_regs->eax)) {
		bool interrupted_restart =
			(EV_SYSCALL_INTERRUPTION == t->ev().type());
		// The tracee was interrupted while attempting to
		// restart a syscall.  We have to look at the previous
		// event to see which syscall we're trying to restart.
		if (interrupted_restart) {
			syscall = t->ev().Syscall().no;
			debug("  interrupted %s interrupted again",
			      syscallname(syscall));
		}
		// During recording, when a syscall exits with a
		// restart "error", the kernel sometimes restarts the
		// tracee by resetting its $ip to the syscall entry
		// point, but other times restarts the syscall without
		// changing the $ip.  In the latter case, we have to
		// leave the syscall return "hanging".  If it's
		// restarted without changing the $ip, we'll skip
		// advancing to the restart entry below and just
		// emulate exit by setting the kernel outparams.
		//
		// It's probably possible to predict which case is
		// going to happen (seems to be for
		// -ERESTART_RESTARTBLOCK and
		// ptrace-declined-signal-delivery restarts), but it's
		// simpler and probably more reliable to just check
		// the tracee $ip at syscall restart to determine
		// whether syscall re-entry needs to occur.
		t->set_return_value_from_trace();
		process_restart_syscall(t, syscall);
		// Use this record to recognize the syscall if it
		// indeed restarts.  If the syscall isn't restarted,
		// we'll pop this event eventually, at the point when
		// the recorder determined that the syscall wasn't
		// going to be restarted.
		if (!interrupted_restart) {
			// For interrupted SYS_restart_syscall's,
			// reuse the restart record, both because
			// that's semantically correct, and because
			// we'll only know how to pop one interruption
			// event later.
			t->push_event(Event(interrupted,
					    SyscallEvent(syscall)));
			t->ev().Syscall().regs = t->regs();
		}
		step->action = TSTEP_RETIRE;
		debug("  %s interrupted by %ld at %p, may restart",
		      syscallname(syscall), rec_regs->eax, (void*)rec_regs->eip);
		return;
	}

	if (SYS_restart_syscall == syscall) {
		assert_exec(t, EV_SYSCALL_INTERRUPTION == t->ev().type(),
			    "Must have interrupted syscall to restart");

		syscall = t->ev().Syscall().no;
		if (STATE_SYSCALL_ENTRY == state) {
			void* intr_ip = (void*)t->ev().Syscall().regs.eip;
			void* cur_ip = (void*)t->ip();

			debug("'restarting' %s interrupted by %ld at %p; now at %p",
			      syscallname(syscall), t->ev().Syscall().regs.eax,
			      intr_ip, cur_ip);
			if (cur_ip == intr_ip) {
				// See long comment above; this
				// "emulates" the restart by just
				// continuing on from the interrupted
				// syscall.
				step->action = TSTEP_RETIRE;
				return;
			}
		} else {
			t->pop_syscall_interruption();
			debug("exiting restarted %s", syscallname(syscall));
		}
	}

	assert_exec(t, syscall < int(ALEN(syscall_table)),
		    "%d not in syscall table, but possibly valid", syscall);

	def = &syscall_table[syscall];
	assert_exec(t, rep_UNDEFINED != def->type,
		    "Valid but unhandled syscallno %d", syscall);

	step->syscall.no = syscall;

	t->maybe_update_vm(syscall, state);

	if (rep_IRREGULAR != def->type) {
		step->syscall.num_emu_args = def->num_emu_args;
		step->action = STATE_SYSCALL_ENTRY == state ?
			       TSTEP_ENTER_SYSCALL : TSTEP_EXIT_SYSCALL;
		step->syscall.emu = rep_EMU == def->type;
		step->syscall.emu_ret =
			rep_EMU == def->type || rep_EXEC_RET_EMU == def->type;
		// TODO: there are several syscalls below that aren't
		// /actually/ irregular, they just want to update some
		// state on syscall exit.  Convert them to use
		// before_syscall_exit().
		if (TSTEP_EXIT_SYSCALL == step->action) {
			before_syscall_exit(t, syscall);
		}
		return;
	}

	assert(rep_IRREGULAR == def->type);

	/* Manual implementations of irregular syscalls. */

	switch (syscall) {
	case SYS_clone:
		return process_clone(t, trace, state, step);

	case SYS_execve:
		return process_execve(t, trace, state, rec_regs, step);

	case SYS_exit:
		destroy_buffers(t, DESTROY_DEFAULT);
		// fall through
	case SYS_exit_group:
		step->syscall.emu = 0;
		assert(state == STATE_SYSCALL_ENTRY);
		step->action = TSTEP_ENTER_SYSCALL;
		return;

	case SYS_fcntl64:
		step->syscall.emu = 1;
		step->syscall.emu_ret = 1;
		if (state == 0) {
			step->action = TSTEP_ENTER_SYSCALL;
		} else {
			int cmd = t->regs().ecx;

			step->action = TSTEP_EXIT_SYSCALL;
			switch (cmd) {
			case F_DUPFD:
			case F_GETFD:
			case F_GETFL:
			case F_SETFL:
			case F_SETFD:
			case F_SETLK:
			case F_SETLK64:
			case F_SETLKW:
			case F_SETLKW64:
			case F_SETOWN:
			case F_SETOWN_EX:
			case F_SETSIG:
				step->syscall.num_emu_args = 0;
				break;
			case F_GETLK:
			case F_GETLK64:
			case F_GETOWN_EX:
				step->syscall.num_emu_args = 1;
				break;
			default:
				fatal("Unknown fcntl64 command: %d", cmd);
			}
		}
		return;

	case SYS_futex:
		return process_futex(t, state, step, rec_regs);

	case SYS_ioctl:
		return process_ioctl(t, state, step);

	case SYS_ipc:
		return process_ipc(t, trace, state, step);

	case SYS_mmap2:
		return process_mmap2(t, trace, state, step);

	case SYS_nanosleep:
		step->syscall.emu = 1;
		step->syscall.emu_ret = 1;
		if (STATE_SYSCALL_ENTRY == state) {
			step->action = TSTEP_ENTER_SYSCALL;
		} else {
			step->action = TSTEP_EXIT_SYSCALL;
			step->syscall.num_emu_args =
				(trace->recorded_regs.ecx != 0) ? 1 : 0;
		}
		return;

	case SYS_prctl: {
		int option = trace->recorded_regs.ebx;
		void* arg2 = (void*)trace->recorded_regs.ecx;
		if (PR_SET_NAME == option || PR_GET_NAME == option) {
			step->syscall.num_emu_args = 1;
			// We actually execute these.
			step->action =
				(STATE_SYSCALL_ENTRY == state) ?
				TSTEP_ENTER_SYSCALL : TSTEP_EXIT_SYSCALL;
			if (TSTEP_EXIT_SYSCALL == step->action) {
				t->update_prname(arg2);
			}
			return;
		}
		step->syscall.emu = 1;
		step->syscall.emu_ret = 1;
		step->syscall.num_emu_args = 1;
		if (STATE_SYSCALL_ENTRY == state) {
			step->action = TSTEP_ENTER_SYSCALL;
			return;
		}
		step->action = TSTEP_EXIT_SYSCALL;
		step->syscall.num_emu_args = 1;
		return;
	}
	case SYS_ptrace:
		step->syscall.emu = 1;
		if (STATE_SYSCALL_ENTRY == state) {
			step->action = TSTEP_ENTER_SYSCALL;
			return;
		}
		// ptrace isn't supported yet, but we bend over
		// backwards to make traces that contain ptrace aborts
		// as pleasantly debuggable as possible.  This is
		// because several crash-monitoring systems use ptrace
		// to generate crash reports, and those are exactly
		// the kinds of events users will want to debug.
		assert_exec(t, false,
			    "Should have reached trace termination.");
		return;		// not reached

	case SYS_quotactl:
		step->syscall.emu = 1;
		step->syscall.emu_ret = 1;
		if (state == STATE_SYSCALL_ENTRY) {
			step->action = TSTEP_ENTER_SYSCALL;
		} else {
			int cmd = t->regs().ebp;

			step->action = TSTEP_EXIT_SYSCALL;
			switch (cmd & SUBCMDMASK) {
			case Q_GETQUOTA:
			case Q_GETINFO:
			case Q_GETFMT:
				step->syscall.num_emu_args = 1;
				break;
			default:
				step->syscall.num_emu_args = 0;
			}
		}
		return;

	case SYS_read:
		step->syscall.emu = 1;
		step->syscall.emu_ret = 1;
		if (STATE_SYSCALL_ENTRY == state) {
			step->action = TSTEP_ENTER_SYSCALL;
		} else {
			step->action = TSTEP_EXIT_SYSCALL;
			step->syscall.num_emu_args = 1;
		}
		return;

	case SYS_recvmmsg: {
		step->syscall.emu = 1;
		step->syscall.emu_ret = 1;
		if (STATE_SYSCALL_ENTRY == state) {
			step->action = TSTEP_ENTER_SYSCALL;
			return;
		}
		struct mmsghdr* msg = (struct mmsghdr*)rec_regs->ecx;
		ssize_t nmmsgs = rec_regs->eax;
		for (int i = 0; i < nmmsgs; ++i, ++msg) {
			restore_struct_mmsghdr(t, msg);
		}
		step->action = TSTEP_EXIT_SYSCALL;
		return;
	}
	case SYS_sendmmsg: {
		step->syscall.emu = 1;
		step->syscall.emu_ret = 1;
		if (STATE_SYSCALL_ENTRY == state) {
			step->action = TSTEP_ENTER_SYSCALL;
			return;
		}
		ssize_t nmmsgs = rec_regs->eax;
		for (int i = 0; i < nmmsgs; ++i) {
			t->set_data_from_trace();
		}
		step->action = TSTEP_EXIT_SYSCALL;
		return;
	}
	case SYS_set_tid_address:
		// set_tid_address returns the caller's PID.
		step->syscall.emu_ret = 1;
		// We have to actually execute set_tid_address in case
		// any crazy code uses it in a clone child.  The
		// kernel actually notifies the futex during replay,
		// so if we didn't update the cleartid addr, then the
		// kernel would randomly scribble over a word in
		// replay that it didn't during recording.
		if (STATE_SYSCALL_ENTRY == state) {
			step->action = TSTEP_ENTER_SYSCALL;
			return;
		}
		step->syscall.num_emu_args = 1;
		step->action = TSTEP_EXIT_SYSCALL;
		t->set_data_from_trace();
		t->set_tid_addr((void*)rec_regs->ebx);
		return;

	case SYS_sigreturn:
	case SYS_rt_sigreturn:
		if (state == STATE_SYSCALL_ENTRY) {
			step->syscall.emu = 1;
			step->action = TSTEP_ENTER_SYSCALL;
			return;
		}
		finish_syscall_emu(t);
		t->set_regs(trace->recorded_regs);
		step->action = TSTEP_RETIRE;
		return;

	case SYS_socketcall:
		return process_socketcall(t, state, step);

	case SYS_write:
	case SYS_writev:
		step->syscall.num_emu_args = 0;
		step->syscall.emu = 1;
		step->syscall.emu_ret = 1;
		if (state == STATE_SYSCALL_ENTRY) {
			step->action = TSTEP_ENTER_SYSCALL;
			return;
		}

		step->action = TSTEP_EXIT_SYSCALL;
		/* XXX technically this will print the output before
		 * we reach the interrupt.  That could maybe cause
		 * issues in the future. */
		rep_maybe_replay_stdio_write(t);
		/* write*() can be desched'd, but don't use scratch,
		 * so we might have saved 0 bytes of scratch after a
		 * desched. */
		maybe_noop_restore_syscallbuf_scratch(t);
		return;

	case SYS_rrcall_init_buffers:
		return process_init_buffers(t, state, step);

	case SYS_rrcall_monkeypatch_vdso:
		step->syscall.num_emu_args = 0;
		step->syscall.emu = 1;
		step->syscall.emu_ret = 1;
		if (STATE_SYSCALL_ENTRY == state) {
			step->action = TSTEP_ENTER_SYSCALL;
			return;
		}
		/* Proceed to syscall exit so we can run our own syscalls. */
		exit_syscall_emu(t, SYS_rrcall_monkeypatch_vdso, 0);
		monkeypatch_vdso(t);
		step->action = TSTEP_RETIRE;
		return;

	default:
		break;
	}

	/* TODO: irregular syscalls that don't understand
	 * trace_step */
	step->action = TSTEP_RETIRE;

	switch (syscall) {
	default:
		fatal("Unhandled irregular syscall %d", syscall);
	}
}
