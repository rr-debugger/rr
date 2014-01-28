/* -*- Mode: C++; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

//#define DEBUGTAG "Task"

#include "task.h"

#include <linux/kdev_t.h>
#include <stdlib.h>
#include <string.h>
#include <syscall.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <set>

#include "dbg.h"
#include "hpc.h"
#include "sys.h"
#include "util.h"

#include "../preload/syscall_buffer.h"

using namespace std;

static Task::Map tasks;
static Task::MapByPriority tasks_by_priority;

/*static*/ AddressSpace::Set AddressSpace::sas;

dev_t
FileId::dev_major() const { return is_real_device() ? MAJOR(device) : 0; }

dev_t
FileId::dev_minor() const { return is_real_device() ? MINOR(device) : 0; }

ino_t
FileId::disp_inode() const { return is_real_device() ? inode : 0; } 

const char*
FileId::special_name() const {
	switch (psdev) {
	case PSEUDODEVICE_ANONYMOUS: return "";
	case PSEUDODEVICE_HEAP: return "(heap)";
	case PSEUDODEVICE_NONE: return "";
	case PSEUDODEVICE_SCRATCH: return "";
	case PSEUDODEVICE_STACK: return "(stack)";
	case PSEUDODEVICE_SYSCALLBUF: return "(syscallbuf)";
	case PSEUDODEVICE_VDSO: return "(vdso)";
	}
	fatal("Not reached");
	return nullptr;
}

void
HasTaskSet::insert_task(Task* t)
{
	debug("adding %d to task set %p", t->tid, this);
	tasks.insert(t);
}

void
HasTaskSet::erase_task(Task* t) {
	debug("removing %d from task group %p", t->tid, this);
	tasks.erase(t);
}

void
AddressSpace::brk(const byte* addr)
{
	debug("[%d] brk(%p)", get_global_time(), addr);

	assert(heap.start <= addr);
	if (addr == heap.end) {
		return;
	}

	update_heap(heap.start, addr);
	map(heap.start, heap.num_bytes(), heap.prot, heap.flags, heap.offset,
	    MappableResource::heap());
}

AddressSpace::shr_ptr
AddressSpace::clone()
{
	return shr_ptr(new AddressSpace(*this));
}

void
AddressSpace::dump() const
{
	fprintf(stderr, "  (heap: %p-%p)\n", heap.start, heap.end);
	for (auto it = mem.begin(); it != mem.end(); ++it) {
		const Mapping& m = it->first;
		const MappableResource& r = it->second;
		fprintf(stderr,
			"%08lx-%08lx %c%c%c%c %08lx %02llx:%02llx %-10ld %s %s (f:0x%x d:0x%llx i:%ld)\n",
			reinterpret_cast<long>(m.start),
			reinterpret_cast<long>(m.end),
			(PROT_READ & m.prot) ? 'r' : '-',
			(PROT_WRITE & m.prot) ? 'w' : '-',
			(PROT_EXEC & m.prot) ? 'x' : '-',
			(MAP_SHARED & m.flags) ? 's' : 'p',
			m.offset,
			r.id.dev_major(), r.id.dev_minor(), r.id.disp_inode(),
			r.fsname.c_str(), r.id.special_name(),
			m.flags, r.id.device, r.id.inode);
	}
}

void
AddressSpace::map(const byte* addr, size_t num_bytes, int prot, int flags,
		  off_t offset, const MappableResource& res)
{
	debug("[%d] mmap(%p, %u, 0x%x, 0x%x)", get_global_time(),
	      addr, num_bytes, prot, flags);

	Mapping m(addr, num_bytes, prot, flags, offset);
	if (mem.end() != mem.find(m)) {
		// The mmap() man page doesn't specifically describe
		// what should happen if an existing map is
		// "overwritten" by a new map (of the same resource).
		// In testing, the behavior seems to be as if the
		// overlapping region is unmapped and then remapped
		// per the arguments to the second call.
		unmap(addr, num_bytes);
	}

	map_and_coalesce(m, res);
}

typedef AddressSpace::MemoryMap::value_type MappingResourcePair;
MappingResourcePair
AddressSpace::mapping_of(const byte* addr, size_t num_bytes)
{
	auto it = mem.find(Mapping(addr, num_bytes));
	assert(it != mem.end());
	// TODO callers assume [addr, addr + num_bytes] doesn't cross
	// resource boundaries
	assert(it->first.has_subset(Mapping(addr, num_bytes)));
	return *it;
}

/**
 * Return the offset of |m| into |r| updated by |delta|, unless |r| is
 * a pseudo-device that doesn't have offsets, in which case the
 * updated offset 0 is returned.
 */
static off_t adjust_offset(const MappableResource& r, const Mapping& m,
			   off_t delta)
{
	return r.id.is_real_device() ? m.offset + delta : 0;
}

void
AddressSpace::protect(const byte* addr, size_t num_bytes, int prot)
{
	debug("[%d] mprotect(%p, %u, 0x%x)", get_global_time(),
	      addr, num_bytes, prot);

	auto mr = mapping_of(addr, num_bytes);
	Mapping m = mr.first;
	MappableResource r = mr.second;

	unmap(addr, num_bytes);

	map_and_coalesce(Mapping(addr, num_bytes, prot, m.flags,
				 adjust_offset(r, m, addr - m.start)),
			 r);
}

void
AddressSpace::remap(const byte* old_addr, size_t old_num_bytes,
		    const byte* new_addr, size_t new_num_bytes)
{
	debug("[%d] mremap(%p, %u, %p, %u)", get_global_time(),
	      old_addr, old_num_bytes, new_addr, new_num_bytes);

	auto mr = mapping_of(old_addr, old_num_bytes);
	const Mapping& m = mr.first;
	const MappableResource& r = mr.second;

	unmap(old_addr, old_num_bytes);
	if (0 == new_num_bytes) {
		return;
	}

	map_and_coalesce(Mapping(new_addr, new_num_bytes, m.prot, m.flags,
				 adjust_offset(r, m, (old_addr - m.start))),
			 r);
}

void
AddressSpace::unmap(const byte* addr, ssize_t num_bytes)
{
	debug("[%d] munmap(%p, %u)", get_global_time(), addr, num_bytes);
	do {
		Mapping u(addr, num_bytes);
		auto it = mem.find(u);
		assert(it != mem.end());

		Mapping m = it->first;
		MappableResource r = it->second;

		mem.erase(m);

		if (m.start < u.start) {
			mem[Mapping(m.start, u.start - m.start, m.prot,
				    m.flags, m.offset)] = r;
		}
		if (u.end < m.end) {
			mem[Mapping(u.end, m.end - u.end, m.prot, m.flags,
				    adjust_offset(r, m, u.start - m.start))]
				= r;
		}

		addr = m.end;
		num_bytes -= m.num_bytes();
	} while (num_bytes > 0);
}

const int checkable_flags_mask = (MAP_PRIVATE | MAP_SHARED);

struct VerifyAddressSpace {
	typedef AddressSpace::MemoryMap::const_iterator const_iterator;

	VerifyAddressSpace(const AddressSpace* as)
		: as(as), it(as->mem.begin()) { }

	const AddressSpace* as;
	const_iterator it;
};

static int assert_segment(void* pvas, Task* t,
			  const struct map_iterator_data* data)
{
	VerifyAddressSpace* vas = static_cast<VerifyAddressSpace*>(pvas);
	const Mapping& m = vas->it->first;
	const struct mapped_segment_info& info = data->info;
	int m_flags = m.flags & checkable_flags_mask;
	assert(info.flags == (info.flags & checkable_flags_mask));
	bool same_mapping = (m.start == info.start_addr
			     && m.end == info.end_addr
			     && m.prot == info.prot
			     && m_flags == info.flags);
	// TODO: "fuzzy matching" to handle differing merge heuristics
	if (!same_mapping) {
		log_err("cached mmap:");
		vas->as->dump();
		log_err("/proc/%d/mmaps:", t->tid);
		print_process_mmap(t);

		assert_exec(t, same_mapping,
			    "Cached mapping '%p-%p 0x%x f:0x%x (0x%x)' should be '%p-%p 0x%x f:0x%x'",
			    m.start, m.end, m.prot, m_flags, m.flags,
			    info.start_addr, info.end_addr,
			    info.prot, info.flags);
	}

	++vas->it;
	return CONTINUE_ITERATING;
}

void
AddressSpace::verify(Task* t) const
{
	assert(task_set().end() != task_set().find(t));

	VerifyAddressSpace vas(this);
	iterate_memory_map(t, assert_segment, &vas, kNeverReadSegment, NULL);
}

/*static*/ AddressSpace::shr_ptr
AddressSpace::create(Task* t)
{
	shr_ptr as(new AddressSpace());
	as->insert_task(t);
	iterate_memory_map(t, populate_address_space, as.get(),
			   kNeverReadSegment, NULL);
	return as;
}

static bool is_adjacent_mapping(const MappingResourcePair& v1,
				const MappingResourcePair& v2)
{
	const Mapping& m1 = v1.first;
	const Mapping& m2 = v2.first;
	if (m1.end != m2.start) {
		debug("    (not adjacent in memory)");
		return false;
	}
	if ((m1.flags & ~MAP_STACK) != (m2.flags & ~MAP_STACK)
	    || m1.prot != m2.prot) {
		debug("    (flags or prot differ)");
		return false;
	}
	const MappableResource& r1 = v1.second;
	const MappableResource& r2 = v2.second;
	if ((MAP_STACK & m1.flags) && (r1.is_stack() || r2.is_stack())) {
		debug("    adjacent stacks");
		return true;
	}
	if (r1.is_scratch() && r2.is_scratch()) {
		// XXX it's annoying to lose the task<->scratch
		// bijection by coalescing in this case, but the
		// kernel doesn't know to avoid merging these.  When
		// scratch memory is mapped from shmem, we can drop
		// this special case and get back the bijection.
		debug("    adjacent scratch");
		return true;
	}
	if (r1 != r2) {
		debug("    (not the same resource)");
		return false;
	}
	if (r1.id.is_real_device() && (off_t(m1.offset + m1.num_bytes()) !=
				       m2.offset)) {
		debug("    (offsets into real device aren't adjacent)");
		return false;
	}
	debug("    adjacent!");
	return true;
}

void
AddressSpace::map_and_coalesce(const Mapping& m, const MappableResource& r)
{
	debug("  mapping %p-%p (prot:0x%d flags:0x%x)",
	      m.start, m.end, m.prot, m.flags);

	auto ins = mem.insert(MemoryMap::value_type(m, r));
	assert(ins.second);	// key didn't already exist

	auto first_kv = ins.first;
	while (mem.begin() != first_kv) {
		auto next = first_kv;
		if (!is_adjacent_mapping(*--first_kv, *next)) {
			first_kv = next;
			break;
		}
	}
	auto last_kv = ins.first;
	while (true) {
		auto prev = last_kv;
		if (mem.end() == ++last_kv
		    || !is_adjacent_mapping(*prev, *last_kv)) {
			last_kv = prev;
			break;
		}
	}
	assert(last_kv != mem.end());
	if (first_kv == last_kv) {
		debug("  no mappings to coalesce");
		return;
	}

	Mapping c(first_kv->first.start, last_kv->first.end, m.prot, m.flags,
		  first_kv->first.offset);
	debug("  coalescing %p-%p", c.start, c.end);

	mem.erase(first_kv, ++last_kv);

	ins = mem.insert(MemoryMap::value_type(c, r));
	assert(ins.second);	// key didn't already exist
}

/*static*/ int
AddressSpace::populate_address_space(void* asp, Task* t,
				     const struct map_iterator_data* data)
{
	AddressSpace* as = static_cast<AddressSpace*>(asp);
	const struct mapped_segment_info& info = data->info;

	if (!as->heap.start) {
		// We assume that the first mapped segment is the
		// program text segment.  It's possible, but not
		// probably, that the end of this segment is the
		// beginning of the dynamic heap segment.  We'll
		// determine that for sure in subsequent iterations.
		//
		// TODO: handle arbitrarily positioned text segments
		assert(info.prot & PROT_EXEC);
		assert(!as->exe.length());

		as->exe = info.name;

		as->update_heap(info.end_addr, info.end_addr);
		debug("  guessing heap starts at %p (end of text segment)",
		      as->heap.start);
	}
	if (as->heap.end == info.start_addr) {
		assert(as->heap.start == as->heap.end);
		assert(!(info.prot & PROT_EXEC));
		as->update_heap(info.end_addr, info.end_addr);
		debug("  updating start-of-heap guess to %p (end of mapped-data segment)",
		      as->heap.start);
	}

	FileId id;
	if (!strcmp("[heap]", info.name)) {
		id.psdev = PSEUDODEVICE_HEAP;
		as->update_heap(info.start_addr, info.end_addr);
	} else if (!strcmp("[stack]", info.name)) {
		id.psdev = PSEUDODEVICE_STACK;
	} else if (!strcmp("[vdso]", info.name)) {
		id.psdev = PSEUDODEVICE_VDSO;
	} else {
		id = FileId(MKDEV(info.dev_major, info.dev_minor), info.inode);
	}

	as->map(info.start_addr, info.end_addr - info.start_addr,
		info.prot, info.flags, info.file_offset,
		MappableResource(id, info.name));

	return CONTINUE_ITERATING;
}

/*static*/ ino_t MappableResource::nr_anonymous_maps;

/**
 * Stores the table of signal dispositions and metadata for an
 * arbitrary set of tasks.  Each of those tasks must own one one of
 * the |refcount|s while they still refer to this.
 */
struct Sighandler {
	Sighandler() : handler(SIG_DFL), resethand(false) { }
	Sighandler(const struct kernel_sigaction& sa)
		: handler(sa.k_sa_handler)
		, resethand(sa.sa_flags & SA_RESETHAND)	{ }

	bool is_default() const {
		return SIG_DFL == handler && !resethand;
	}
	bool is_user_handler() const {
		static_assert((void*)1 == SIG_IGN, "");
		return (uintptr_t)handler & ~(uintptr_t)SIG_IGN;
	}

	sig_handler_t handler;
	bool resethand;
};
struct Sighandlers {
	typedef shared_ptr<Sighandlers> shr_ptr;

	shr_ptr clone() const {
		shr_ptr s(new Sighandlers());
		// NB: depends on the fact that Sighandler is for all
		// intents and purposes a POD type, though not
		// technically.
		memcpy(s->handlers, handlers, sizeof(handlers));
		return s;
	}

	Sighandler& get(int sig) {
		assert_valid(sig);
		return handlers[sig];
	}
	const Sighandler& get(int sig) const {
		assert_valid(sig);
		return handlers[sig];
	}

	void init_from_current_process() {
		for (int i = 0; i < ssize_t(ALEN(handlers)); ++i) {
			Sighandler& h = handlers[i];
			struct sigaction act;
			if (-1 == sigaction(i, NULL, &act)) {
				/* EINVAL means we're querying an
				 * unused signal number. */
				assert(EINVAL == errno);
				assert(h.is_default());
				continue;
			}
			struct kernel_sigaction ka;
			ka.k_sa_handler = act.sa_handler;
			ka.sa_flags = act.sa_flags;
			ka.sa_restorer = act.sa_restorer;
			ka.sa_mask = act.sa_mask;
			h = Sighandler(ka);
		}
	}

	/**
	 * For each signal in |table| such that is_user_handler() is
	 * true, reset the disposition of that signal to SIG_DFL, and
	 * clear the resethand flag if it's set.  SIG_IGN signals are
	 * not modified.
	 *
	 * (After an exec() call copies the original sighandler table,
	 * this is the operation required by POSIX to initialize that
	 * table copy.)
	 */
	void reset_user_handlers() {
		for (int i = 0; i < ssize_t(ALEN(handlers)); ++i) {
			Sighandler& h = handlers[i];
			// If the handler was a user handler, reset to
			// default.  If it was SIG_IGN or SIG_DFL,
			// leave it alone.
			if (h.is_user_handler()) {
				handlers[i] = Sighandler();
			}
		}
	}

	static void assert_valid(int sig) {
		assert(0 < sig && sig < ssize_t(ALEN(handlers)));
	}

	static shr_ptr create() {
		return shr_ptr(new Sighandlers());
	}

	Sighandler handlers[_NSIG];

private:
	Sighandlers() { }
	Sighandlers(const Sighandlers&);
	Sighandlers operator=(const Sighandlers&);
};

/**
 * Tracks a group of tasks with an associated ID, set from the
 * original "thread group leader", the child of |fork()| which became
 * the ancestor of all other threads in the group.  Each constituent
 * task must own a reference to this.
 */
struct TaskGroup : public HasTaskSet {
	typedef shared_ptr<TaskGroup> shr_ptr;

	void destabilize() {
		debug("destabilizing task group %d", tgid);
		for (auto it = task_set().begin(); it != task_set().end(); ++it) {
			Task* t = *it;
			t->unstable = 1;
			debug("  destabilized task %d", t->tid);
		}
	}

	static shr_ptr create(Task* t) {
		shr_ptr tg(new TaskGroup(t->tid));
		tg->insert_task(t);
		return tg;
	}

	pid_t tgid;

private:
	TaskGroup(pid_t tgid) : tgid(tgid) {
		debug("creating new task group %d", tgid);
	}
	TaskGroup(const TaskGroup&);
	TaskGroup operator=(const TaskGroup&);
};

static const char* event_type_name(int type)
{
	switch (type) {
	case EV_SENTINEL: return "(none)";
#define CASE(_t) case EV_## _t: return #_t
	CASE(DESCHED);
	CASE(PSEUDOSIG);
	CASE(SIGNAL);
	CASE(SIGNAL_DELIVERY);
	CASE(SIGNAL_HANDLER);
	CASE(SYSCALL);
	CASE(SYSCALL_INTERRUPTION);
#undef CASE
	default:
		fatal("Unknown event type %d", type);
	}
}

static int is_syscall_event(int type) {
	switch (type) {
	case EV_SYSCALL:
	case EV_SYSCALL_INTERRUPTION:
		return 1;
	default:
		return 0;
	}
}

/**
 * Detach |t| from rr and try hard to ensure any operations related to
 * it have completed by the time this function returns.
 */
static void detach_and_reap(Task* t)
{
	sys_ptrace_detach(t->tid);
	if (t->unstable) {
		log_warn("%d is unstable; not blocking on its termination",
			 t->tid);
		goto sleep_hack;
	}

	debug("Joining with exiting %d ...", t->tid);
	while (1) {
		int err = waitpid(t->tid, &t->status, __WALL);
		if (-1 == err && ECHILD == errno) {
			debug(" ... ECHILD");
			break;
		} else if (-1 == err) {
			assert_exec(t, EINTR == errno,
				    "waitpid(%d) returned -1, errno %d",
				    t->tid, errno);
		}
		if (err == t->tid && (WIFEXITED(t->status) || 
				      WIFSIGNALED(t->status))) {
			debug(" ... exited with status 0x%x", t->status);
			break;
		} else if (err == t->tid) {
			assert_exec(t, (PTRACE_EVENT_EXIT ==
					GET_PTRACE_EVENT(t->status)),
				    "waitpid(%d) return status %d",
				    t->tid, t->status);
		}
	}

sleep_hack:
	/* clone()'d tasks can have a pid_t* |ctid| argument that's
	 * written with the new task's pid.  That pointer can also be
	 * used as a futex: when the task dies, the original ctid
	 * value is cleared and a FUTEX_WAKE is done on the
	 * address. So pthread_join() is basically a standard futex
	 * wait loop.
	 *
	 * That means that the kernel writes shared memory behind rr's
	 * back, which can diverge replay.  The "real fix" for this is
	 * for rr to track access to shared memory, like the |ctid|
	 * location.  But until then, we (attempt to) let "time"
	 * resolve this memory race with the sleep() hack below.
	 *
	 * Why 4ms?  Because
	 *
	 * $ for i in $(seq 10); do (cd $rr/src/test/ && bash thread_cleanup.run) & done
	 *
	 * has been observed to fail when we sleep 3ms, but not when
	 * we sleep 4ms.  Yep, this hack is that horrible! */
	struct timespec ts;
	memset(&ts, 0, sizeof(ts));
	ts.tv_nsec = 4000000LL;
	nanosleep_nointr(&ts);
}

Task::Task(pid_t _tid, pid_t _rec_tid, int _priority)
{
	// TODO: properly C++-ify me
	memset(this, 0, sizeof(*this));

	tid = _tid;
	rec_tid = _rec_tid > 0 ? _rec_tid : tid;
	thread_time = 1;
	child_mem_fd = sys_open_child_mem(this);
	// These will be initialized when the syscall buffer is.
	desched_fd = desched_fd_child = -1;
	if (RECORD != rr_flags()->option) {
		// This flag isn't meaningful outside recording.
		// Suppress output related to it outside recording.
		switchable = 1;
	}
	priority = _priority;
	tasks_by_priority[_priority].push_back(this);

	push_placeholder_event(this);

	init_hpc(this);

	tasks[rec_tid] = this;
}

static void
remove_task_from_map_by_priority(Task* t)
{
	list<Task*>& list = tasks_by_priority[t->priority];
	list.remove(t);
	if (list.empty()) {
		tasks_by_priority.erase(t->priority);
	}
}

Task::~Task()
{
	debug("task %d (rec:%d) is dying ...", tid, rec_tid);

	assert(this == Task::find(rec_tid));
	// We expect tasks to usually exit by a call to exit() or
	// exit_group(), so it's not helpful to warn about that.
	if (EV_SENTINEL != ev->type
	    && (FIXEDSTACK_DEPTH(&pending_events) > 2
		|| !(ev->type == EV_SYSCALL
		     && (SYS_exit == ev->syscall.no
			 || SYS_exit_group == ev->syscall.no)))) {
		log_warn("%d still has pending events.  From top down:", tid);
		log_pending_events(this);
	}

	tasks.erase(rec_tid);
	task_group->erase_task(this);
	as->erase_task(this);
	remove_task_from_map_by_priority(this);

	destroy_hpc(this);
	close(child_mem_fd);
	close(desched_fd);
	munmap(syscallbuf_hdr, num_syscallbuf_bytes);

	detach_and_reap(this);

	debug("  dead");
}

Task*
Task::clone(int flags, const byte* stack, pid_t new_tid, pid_t new_rec_tid)
{
	Task* t = new Task(new_tid, new_rec_tid, priority);

	t->syscallbuf_lib_start = syscallbuf_lib_start;
	t->syscallbuf_lib_end = syscallbuf_lib_end;
	if (CLONE_SHARE_SIGHANDLERS & flags) {
		t->sighandlers = sighandlers;
	} else {
		auto sh = Sighandlers::create();
		t->sighandlers.swap(sh);
	}
	if (CLONE_SHARE_TASK_GROUP & flags) {
		t->task_group = task_group;
		task_group->insert_task(t);
	} else {
		auto tg = TaskGroup::create(t);
		t->task_group.swap(tg);
	}
	if (CLONE_SHARE_VM & flags) {
		t->as = as;
	} else {
		t->as = as->clone();
	}
	if (stack) {
		const Mapping& m =
			t->as->mapping_of(stack - page_size(), page_size()).first;
		debug("mapping stack for %d at [%p, %p)", new_tid, m.start, m.end);
		t->as->map(m.start, m.num_bytes(), m.prot, m.flags, m.offset,
			   MappableResource::stack(new_tid));
	} else {
		assert_exec(this, CLONE_SHARE_NOTHING == flags,
			    "No explicit stack for fork()-clone");
	}

	t->as->insert_task(t);
	return t;
}

const struct syscallbuf_record*
Task::desched_rec() const
{
	return (is_syscall_event(ev->type) ? ev->syscall.desched_rec :
		(EV_DESCHED == ev->type) ? ev->desched.rec : NULL);
}

void
Task::destabilize_task_group()
{
	task_group->destabilize();
}

void
Task::dump(FILE* out) const
{
	out = out ? out : LOG_FILE;
	fprintf(out, "  Task<%p>(tid:%d rec_tid:%d status:0x%x%s%s)\n",
		this, tid, rec_tid, status,
		switchable ? "" : " UNSWITCHABLE",
		unstable ? " UNSTABLE" : "");
	if (RECORD == rr_flags()->option) {
		// TODO pending events are currently only meaningful
		// during recording.  We should change that
		// eventually, to have more informative output.
		log_pending_events(this);
	}
}

Task::set_priority(int value)
{
	if (priority == value) {
		// don't mess with task order
		return;
	}
	remove_task_from_map_by_priority(this);
	priority = value;
	tasks_by_priority[priority].push_back(this);
}

const Task::MapByPriority&
Task::get_map_by_priority()
{
	return tasks_by_priority;
}

bool
Task::fdstat(int fd, struct stat* st, char* buf, size_t buf_num_bytes)
{
	char path[PATH_MAX];
	snprintf(path, sizeof(path) - 1, "/proc/%d/fd/%d", tid, fd);
	ScopedOpen backing_fd(path, O_RDONLY);
	if (0 > backing_fd) {
		return false;
	}
	ssize_t nbytes = readlink(path, buf, buf_num_bytes);
	if (0 > nbytes) {
		return false;
	}
	buf[nbytes] = '\0';
	return 0 == fstat(backing_fd, st);
}

bool
Task::may_be_blocked() const
{
	return (ev && ((EV_SYSCALL == ev->type
			&& PROCESSING_SYSCALL == ev->syscall.state)
		       || (EV_SIGNAL_DELIVERY == ev->type
			   && ev->signal.delivered)));
}

void
Task::maybe_update_vm(int syscallno, int state,
		      const struct user_regs_struct& regs)
{
	if (STATE_SYSCALL_EXIT != state || SYSCALL_FAILED(regs.eax)) {
		return;
	}
	switch (syscallno) {
	case SYS_brk: {
		byte* addr = reinterpret_cast<byte*>(regs.ebx);
		if (!addr) {
			// A brk() update of NULL is observed with
			// libc, which apparently is its means of
			// finding out the initial brk().  We can
			// ignore that for the purposes of updating
			// our address space.
			return;
		}
		return vm()->brk(addr);
	}
	case SYS_mmap2: {
		debug("(mmap2 will receive / has received direct processing)");
		return;
	}
	case SYS_mprotect: {
		//int mprotect(void *addr, size_t len, int prot);
		byte* addr = reinterpret_cast<byte*>(regs.ebx);
		size_t num_bytes = regs.ecx;
		int prot = regs.edx;
		return vm()->protect(addr, num_bytes, prot);
	}
	case SYS_mremap: {
		byte* old_addr = reinterpret_cast<byte*>(regs.ebx);
		size_t old_num_bytes = regs.ecx;
		byte* new_addr = reinterpret_cast<byte*>(regs.eax);
		size_t new_num_bytes = regs.edx;
		return vm()->remap(old_addr, old_num_bytes,
				   new_addr, new_num_bytes);
	}
	case SYS_munmap: {
		byte* addr = reinterpret_cast<byte*>(regs.ebx);
		size_t num_bytes = regs.ecx;
		return vm()->unmap(addr, num_bytes);
	}
	}
}

void
Task::post_exec()
{
	sighandlers = sighandlers->clone();
	sighandlers->reset_user_handlers();
	auto a = AddressSpace::create(this);
	as.swap(a);
}

void
Task::set_signal_disposition(int sig, const struct kernel_sigaction& sa)
{
	sighandlers->get(sig) = Sighandler(sa);
}

void
Task::signal_delivered(int sig)
{
	Sighandler& h = sighandlers->get(sig);
	if (h.resethand) {
		h = Sighandler();
	}
}

bool
Task::signal_has_user_handler(int sig) const
{
	return sighandlers->get(sig).is_user_handler();
}

pid_t
Task::tgid() const
{
	return task_group->tgid;
}

/*static*/ Task::Map::const_iterator
Task::begin()
{
	return tasks.begin();
}

/*static*/ ssize_t
Task::count()
{
	return tasks.size();
}

/*static*/ Task*
Task::create(pid_t tid, pid_t rec_tid)
{
	assert(Task::count() == 0);

	Task* t = new Task(tid, rec_tid, 0);
	// The very first task we fork inherits the signal
	// dispositions of the current OS process (which should all be
	// default at this point, but ...).  From there on, new tasks
	// will transitively inherit from this first task.
	auto sh = Sighandlers::create();
	sh->init_from_current_process();
	t->sighandlers.swap(sh);
	auto tg = TaskGroup::create(t);
	t->task_group.swap(tg);
	auto as = AddressSpace::create(t);
	t->as.swap(as);
	return t;
}

/*static*/ void
Task::dump_all(FILE* out)
{
	out = out ? out : LOG_FILE;

	auto sas = AddressSpace::set();
	for (auto ait = sas.begin(); ait != sas.end(); ++ait) {
		const AddressSpace* as = *ait;
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

/*static*/ Task::Map::const_iterator
Task::end()
{
	return tasks.end();
}

/*static*/Task*
Task::find(pid_t rec_tid)
{
	auto it = tasks.find(rec_tid);
	return tasks.end() != it ? it->second : NULL;
}

/**
 * Push a new event onto |t|'s event stack of type |type|.
 */
static void push_new_event(Task* t, EventType type)
{
	struct event ev;
	memset(&ev, 0, sizeof(ev));
	ev.type = EventType(type);

	FIXEDSTACK_PUSH(&t->pending_events, ev);
	t->ev = FIXEDSTACK_TOP(&t->pending_events);
}

/**
 * Pop the pending-event stack and return the type of the previous top
 * element.
 */
static void pop_event(Task* t, int expected_type)
{
	int last_top_type;

	assert_exec(t, FIXEDSTACK_DEPTH(&t->pending_events) > 1,
		    "Attempting to pop sentinel event");

	last_top_type = FIXEDSTACK_POP(&t->pending_events).type;
	t->ev = FIXEDSTACK_TOP(&t->pending_events);
	assert_exec(t, expected_type == last_top_type,
		    "Should have popped event %s but popped %s instead",
		    event_type_name(expected_type),
		    event_type_name(last_top_type));
}

void push_placeholder_event(Task* t)
{
	assert(FIXEDSTACK_EMPTY(&t->pending_events));
	push_new_event(t, EV_SENTINEL);
}

void push_desched(Task* t, const struct syscallbuf_record* rec)
{
	assert_exec(t, !t->desched_rec(), "Must have zero or one desched");

	push_new_event(t, EV_DESCHED);
	t->ev->desched.state = IN_SYSCALL;
	t->ev->desched.rec = rec;
}

void pop_desched(Task* t)
{
	assert_exec(t, t->desched_rec(), "Must have desched_rec to pop");

	pop_event(t, EV_DESCHED);
}

void push_pseudosig(Task* t, PseudosigType no, int has_exec_info)
{
	push_new_event(t, EV_PSEUDOSIG);
	t->ev->pseudosig.no = no;
	t->ev->pseudosig.has_exec_info = has_exec_info;
}

void pop_pseudosig(Task* t)
{
	pop_event(t, EV_PSEUDOSIG);
}

void push_pending_signal(Task* t, int no, int deterministic)
{
	push_new_event(t, EV_SIGNAL);
	t->ev->signal.no = no;
	t->ev->signal.deterministic = deterministic;
}

void pop_signal_delivery(Task* t)
{
	pop_event(t, EV_SIGNAL_DELIVERY);
}

void pop_signal_handler(Task* t)
{
	pop_event(t, EV_SIGNAL_HANDLER);
}

void push_syscall(Task* t, int no)
{
	push_new_event(t, EV_SYSCALL);
	t->ev->syscall.no = no;
}

void pop_syscall(Task* t)
{
	pop_event(t, EV_SYSCALL);
}

void push_syscall_interruption(Task* t, int no,
			       const struct user_regs_struct* args)
{
	const struct syscallbuf_record* rec = t->desched_rec();

	assert_exec(t, rec || REPLAY == rr_flags()->option,
		    "Must be interrupting desched during recording");

	push_new_event(t, EV_SYSCALL_INTERRUPTION);
	t->ev->syscall.state = EXITING_SYSCALL;
	t->ev->syscall.no = no;
	t->ev->syscall.desched_rec = rec;
	memcpy(&t->ev->syscall.regs, args, sizeof(t->ev->syscall.regs));
}

void pop_syscall_interruption(Task* t)
{
	pop_event(t, EV_SYSCALL_INTERRUPTION);
}

void log_pending_events(const Task* t)
{
	ssize_t depth = FIXEDSTACK_DEPTH(&t->pending_events);
	int i;

	assert(depth > 0);
	if (1 == depth) {
		log_info("(no pending events)");
		return;
	}

	/* The event at depth 0 is the placeholder event, which isn't
	 * useful to log.  Skip it. */
	for (i = depth - 1; i >= 1; --i) {
		log_event(&t->pending_events.elts[i]);
	}
}

void log_event(const struct event* ev)
{
	const char* name = event_name(ev);
	switch (ev->type) {
	case EV_SENTINEL:
		log_info("%s", name);
		return;
	case EV_DESCHED:
		log_info("%s: %s", name,
			 syscallname(ev->desched.rec->syscallno));
		break;
	case EV_PSEUDOSIG:
		log_info("%s: %d", name, ev->pseudosig.no);
		return;
	case EV_SIGNAL:
	case EV_SIGNAL_DELIVERY:
	case EV_SIGNAL_HANDLER:
		log_info("%s: %s", name, signalname(ev->signal.no));
		return;
	case EV_SYSCALL:
	case EV_SYSCALL_INTERRUPTION:
		log_info("%s: %s", name, syscallname(ev->syscall.no));
		return;
	default:
		fatal("Unknown event type %d", ev->type);
	}
}

const char* event_name(const struct event* ev)
{
	return event_type_name(ev->type);
}
