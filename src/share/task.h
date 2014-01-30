/* -*- Mode: C++; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#ifndef TASK_H_
#define TASK_H_

// Define linux-specific flags in mman.h.
#define __USE_MISC 1

#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/queue.h>
#include <sys/user.h>

#include <map>
#include <memory>
#include <set>
#include <utility>

#include "fixedstack.h"
#include "trace.h"
#include "util.h"

struct Sighandlers;
class Task;
struct TaskGroup;

struct syscallbuf_hdr;
struct syscallbuf_record;

/* (There are various GNU and BSD extensions that define this, but
 * it's not worth the bother to sort those out.) */
typedef void (*sig_handler_t)(int);

/**
 * The kernel SYS_sigaction ABI is different from the libc API; this
 * is the kernel layout.  We see these at SYS_sigaction traps.
 */
struct kernel_sigaction {
	sig_handler_t k_sa_handler;
	unsigned long sa_flags;
	void (*sa_restorer) (void);
	sigset_t sa_mask;
};

/**
 * PseudoDevices aren't real disk devices, but they differentiate
 * memory mappings when we're trying to decide whether adjacent
 * FileId::NO_DEVICE mappings should be coalesced.
 */
enum PseudoDevice {
	PSEUDODEVICE_NONE = 0,
	PSEUDODEVICE_ANONYMOUS,
	PSEUDODEVICE_HEAP,
	PSEUDODEVICE_SCRATCH,
	PSEUDODEVICE_STACK,
	PSEUDODEVICE_SYSCALLBUF,
	PSEUDODEVICE_VDSO,
};

/**
 * FileIds uniquely identify a file at a point in time (when the file
 * is stat'd).
 */
struct FileId {
	static const dev_t NO_DEVICE = 0;
	static const ino_t NO_INODE = 0;

	FileId() : device(NO_DEVICE), inode(NO_INODE)
		 , psdev(PSEUDODEVICE_NONE) { }
	FileId(const struct stat& st)
		: device(st.st_dev), inode(st.st_ino)
		, psdev(PSEUDODEVICE_NONE) { }
	FileId(dev_t dev, ino_t ino, PseudoDevice psdev = PSEUDODEVICE_NONE)
		: device(dev), inode(ino), psdev(psdev) { }
	FileId(dev_t dev_major, dev_t dev_minor, ino_t ino,
	       PseudoDevice psdev = PSEUDODEVICE_NONE);

	/**
	 * Return the major/minor ID for the device underlying this
	 * file.  If |is_real_device()| is false, return 0
	 * (NO_DEVICE).
	 */
	dev_t dev_major() const;
	dev_t dev_minor() const;
	/**
	 * Return a displayabale "real" inode.  If |is_real_device()|
	 * is false, return 0 (NO_INODE).
	 */
	ino_t disp_inode() const;
	/**
	 * Return true iff |this| and |o| are the same "real device"
	 * (i.e., same device and inode), or |this| and |o| are
	 * ANONYMOUS pseudo-devices.  Results are undefined for other
	 * pseudo-devices.
	 */
	bool equivalent_to(const FileId& o) const {
		return psdev == o.psdev
			&& (psdev == PSEUDODEVICE_ANONYMOUS
			    || (device == o.device && inode == o.inode));
	}
	/**
	 * Return true if this file is/was backed by an external
	 * device, as opposed to a transient RAM mapping.
	 */
	bool is_real_device() const { return device > NO_DEVICE; }
	const char* special_name() const;

	bool operator<(const FileId& o) const {
		return psdev != o.psdev ? psdev < o.psdev :
			device != o.device ? device < o.device :
			inode < o.inode;
	}

	dev_t device;
	ino_t inode;
	PseudoDevice psdev;
};

class HasTaskSet {
public:
	typedef std::set<Task*> TaskSet;

	const TaskSet& task_set() const { return tasks; }

	void insert_task(Task* t);
	void erase_task(Task* t);
protected:
	TaskSet tasks;
};

/**
 * Describe the mapping of a MappableResource.  This includes the
 * offset of the mapping, its protection flags, the offest within the
 * resource, and more.
 */
struct Mapping {
	/**
	 * These are the flags we track internally to distinguish
	 * between adjacent segments.  For example, the kernel
	 * considers a NORESERVE anonynmous mapping that's adjacent to
	 * a non-NORESERVE mapping distinct, even if all other
	 * metadata are the same.  See |is_adjacent_mapping()| in
	 * task.cc.
	 */
	static const int map_flags_mask =
		(MAP_ANONYMOUS | MAP_NORESERVE | MAP_PRIVATE |
		 MAP_SHARED | MAP_STACK);
	static const int checkable_flags_mask = (MAP_PRIVATE | MAP_SHARED);

	Mapping() : start(nullptr), end(nullptr), prot(0), flags(0), offset(0)
	{ }
	Mapping(const byte* addr, size_t num_bytes)
		: start(addr), end(addr + ceil_page_size(num_bytes))
		, prot(0), flags(0), offset(0) {
		assert_valid();
	}
	Mapping(const byte* addr, size_t num_bytes, int prot, int flags,
		off_t offset)
		: start(addr), end(addr + ceil_page_size(num_bytes))
		, prot(prot)
		, flags(flags & map_flags_mask)
		, offset(offset) {
		assert_valid();
	}
	Mapping(const byte* start, const byte* end, int prot, int flags,
		off_t offset)
		: start(start), end(end), prot(prot)
		, flags(flags & map_flags_mask)
		, offset(offset) {
		assert_valid();
	}

	Mapping(const Mapping& o)
		: start(o.start), end(o.end), prot(o.prot), flags(o.flags)
		, offset(o.offset) {
		assert_valid();
	}
	Mapping operator=(const Mapping& o) {
		memcpy(this, &o, sizeof(*this));
		assert_valid();
		return *this;
	}

	void assert_valid() const {
		assert(end >= start);
		assert(num_bytes() % page_size() == 0);
		assert(!(flags & ~map_flags_mask));
	}

	/**
	 * Return true iff |o| is an address range fully contained by
	 * this.
	 */
	bool has_subset(const Mapping& o) const {
		return start <= o.start && o.end <= end;
	}

	/**
	 * Return true iff |o| and this map at least one shared byte.
	 */
	bool intersects(const Mapping& o) const {
		return (start == o.start && o.end == end)
			|| (start <= o.start && o.start < end)
			|| (start < o.end && o.end <= end);
	}

	size_t num_bytes() const { return end - start; }

	/**
	 * Return the lowest-common-denominator interpretation of this
	 * mapping, namely, the one that can be parsed out of
	 * /proc/maps.
	 */
	Mapping to_kernel() const {
		return Mapping(start, end, prot, flags & checkable_flags_mask,
			       offset);
	}

	const byte* const start;
	const byte* const end;
	const int prot;
	const int flags;
	const off_t offset;
};

/**
 * Compare |a| and |b| so that "subset" lookups will succeed.  What
 * does that mean?  If |a| and |b| overlap (intersect), then this
 * comparator considers them equivalent.  That means that if |a|
 * represents one byte within a mapping |b|, then |a| and |b| will be
 * considered equivalent.
 *
 * If |a| and |b| don't overlap, return true if |a|'s start addres is
 * less than |b|'s/
 */
struct MappingComparator {
	bool operator()(const Mapping& a, const Mapping& b) {
		return a.intersects(b) ? false : a.start < b.start;
	}
};

/**
 * A resource that can be mapped into RAM.  |Mapping| represents a
 * mapping into RAM of a MappableResource.
 */
struct MappableResource {
	MappableResource() : id(FileId()) { }
	MappableResource(const FileId& id) : id(id) { }
	MappableResource(const FileId& id, const char* fsname)
		: id(id), fsname(fsname) { }

	bool operator==(const MappableResource& o) const {
		return id.equivalent_to(o.id);
	}
	bool operator!=(const MappableResource& o) const {
		return !(*this == o);
	}
	bool is_scratch() const {
		return PSEUDODEVICE_SCRATCH == id.psdev;
	}
	bool is_stack() const {
		return PSEUDODEVICE_STACK == id.psdev;
	}

	/**
	 * Return a representation of this resource that would be
	 * parsed from /proc/maps if this were mapped.
	 */
	MappableResource to_kernel() const {
		return MappableResource(FileId(id.dev_major(), id.dev_minor(),
					       id.disp_inode()),
					fsname.c_str());
	}

	static MappableResource anonymous() {
		return FileId(FileId::NO_DEVICE, nr_anonymous_maps++,
			      PSEUDODEVICE_ANONYMOUS);
	}
	static MappableResource heap() {
		return MappableResource(
			FileId(FileId::NO_DEVICE, FileId::NO_INODE,
			       PSEUDODEVICE_HEAP),
			"[heap]");
	}
	static MappableResource scratch(pid_t tid) {
		return MappableResource(FileId(FileId::NO_DEVICE, tid,
					       PSEUDODEVICE_SCRATCH),
					"[scratch]");
	}
	static MappableResource stack(pid_t tid) {
		return MappableResource(FileId(FileId::NO_DEVICE, tid,
					       PSEUDODEVICE_STACK),
					"[stack]");
	}
	static MappableResource syscallbuf(pid_t tid, int fd);

	FileId id;
	/**
	 * Some name that this file may have on its underlying file
	 * system.  Not used for anything other than labelling mapped
	 * segments.
	 */
	std::string fsname;

	static ino_t nr_anonymous_maps;
};

/**
 * Models the address space for a set of tasks.  This includes the set
 * of mapped pages, and the resources those mappings refer to.
 */
class AddressSpace : public HasTaskSet {
	friend struct VerifyAddressSpace;

public:
	typedef std::map<Mapping, MappableResource,
			 MappingComparator> MemoryMap;
	typedef std::shared_ptr<AddressSpace> shr_ptr;
	typedef std::set<AddressSpace*> Set;

	~AddressSpace() { sas.erase(this); }

	/** Return an iterator at the beginning of the memory map. */
	MemoryMap::const_iterator begin() const {
		return mem.begin();
	}

	/**
	 * Change the program data break of this address space to
	 * |addr|.
	 */
	void brk(const byte* addr);

	/**
	 * Return a copy of this address space with the same mappings.
	 * If any mapping is changed, only the |clone()|d copy is
	 * updated, not its origin (i.e. copy-on-write semantics).
	 */
	shr_ptr clone();

	/**
	 * Dump a representation of |this| to stderr in a format
	 * similar to /proc/[tid]/maps.
	 *
	 * XXX/ostream-ify me.
	 */
	void dump() const;

	/** Return an iterator at the end of the memory map. */
	MemoryMap::const_iterator end() const {
		return mem.end();
	}

	/**
	 * Return the path this address space was exec()'d with.
	 */
	const std::string& exe_image() const { return exe; }

	/**
	 * Map |num_bytes| into this address space at |addr|, with
	 * |prot| protection and |flags|.  The pages are (possibly
	 * initially) backed starting at |offset| of |res|.
	 */
	void map(const byte* addr, size_t num_bytes, int prot, int flags,
		 off_t offset, const MappableResource& res);

	/**
	 * Return the mapping and mapped resource that underly [addr,
	 * addr + num_bytes).  There must be exactly one such mapping.
	 */
	MemoryMap::value_type mapping_of(const byte* addr, size_t num_bytes);

	/**
	 * Change the protection bits of [addr, addr + num_bytes) to
	 * |prot|.
	 */
	void protect(const byte* addr, size_t num_bytes, int prot);

	/**
	 * Move the mapping [old_addr, old_addr + old_num_bytes) to
	 * [new_addr, old_addr + new_num_bytes), preserving metadata.
	 */
	void remap(const byte* old_addr, size_t old_num_bytes,
		   const byte* new_addr, size_t new_num_bytes);

	/**
	 * Make [addr, addr + num_bytes) inaccesible within this
	 * address space.
	 */
	void unmap(const byte* addr, ssize_t num_bytes);

	/**
	 * Verify that this cached address space matches what the
	 * kernel thinks it should be.
	 */
	void verify(Task* t) const;

	static const Set& set() { return sas; }

	/**
	 * Create and return a new address space that's a copy of the
	 * current address space of |t|.
	 */
	static shr_ptr create(Task* t);

private:
	AddressSpace() {
		sas.insert(this);
	}
	AddressSpace(const AddressSpace& o)
		: exe(o.exe), heap(o.heap), mem(o.mem) {
		sas.insert(this);
	}

	/**
	 * Map |m| of |r| into this address space, and coalesce any
	 * mappings of |r| that are adjacent to |m|.
	 */
	void map_and_coalesce(const Mapping& m, const MappableResource& r);

	/** Set the dynamic heap segment to |[start, end)| */
	void update_heap(const byte* start, const byte* end) {
		heap = Mapping(start, end - start, PROT_READ | PROT_WRITE,
			       MAP_ANONYMOUS | MAP_PRIVATE, 0);
	}

	/**
	 * Path of the executable image this address space was
	 * exec()'d with.
	 */
	std::string exe;
	/**
	 * Track the special process-global heap in order to support
	 * adjustments by brk().
	 */
	Mapping heap;
	/** All segments mapped into this address space. */
	MemoryMap mem;

	/**
	 * Ensure that the cached mapping of |t| matches /proc/maps,
	 * using adjancent-map-merging heuristics that are as lenient
	 * as possible given the data available from /proc/maps.
	 */
	static int check_segment_iterator(void* vasp, Task* t,
					  const struct map_iterator_data* data);

	/**
	 * After an exec, populate the new address space of |t| with
	 * the existing mappings we find in /proc/maps.
	 */
	static int populate_address_space(void* asp, Task* t,
					  const struct map_iterator_data* data);

	static Set sas;

	AddressSpace operator=(const AddressSpace&) = delete;
};

enum PseudosigType {
	ESIG_NONE,
	ESIG_SEGV_MMAP_READ, ESIG_SEGV_MMAP_WRITE, ESIG_SEGV_RDTSC,
	EUSR_EXIT, EUSR_SCHED, EUSR_NEW_RAWDATA_FILE,
	EUSR_SYSCALLBUF_FLUSH, EUSR_SYSCALLBUF_ABORT_COMMIT,
	EUSR_SYSCALLBUF_RESET,
	EUSR_UNSTABLE_EXIT,
	EUSR_TRACE_TERMINATION,
};

enum EventType {
	EV_SENTINEL,
	/* Uses the .desched struct below. */
	EV_DESCHED,
	/* Uses .pseudosig. */
	EV_PSEUDOSIG,
	/* Use .signal. */
	EV_SIGNAL,
	EV_SIGNAL_DELIVERY,
	EV_SIGNAL_HANDLER,
	/* Use .syscall. */
	EV_SYSCALL,
	EV_SYSCALL_INTERRUPTION,
};

enum DeschedState { IN_SYSCALL,
		    DISARMING_DESCHED_EVENT, DISARMED_DESCHED_EVENT };

enum SyscallState { NO_SYSCALL,
		    ENTERING_SYSCALL, PROCESSING_SYSCALL, EXITING_SYSCALL };

/**
 * Events are interesting occurrences during tracee execution which
 * are relevant for replay.  Most events correspond to tracee
 * execution, but some (a subset of "pseudosigs") save actions that
 * the *recorder* took on behalf of the tracee.
 */
struct event {
	EventType type;
	union {
		/**
		 * Desched events track the fact that a tracee's
		 * desched-event notification fired during a may-block
		 * buffered syscall, which rr interprets as the
		 * syscall actually blocking (for a potentially
		 * unbounded amount of time).  After the syscall
		 * exits, rr advances the tracee to where the desched
		 * is "disarmed" by the tracee.
		 */
		struct {
			DeschedState state;
			/* Record of the syscall that was interrupted
			 * by a desched notification.  It's legal to
			 * reference this memory /while the desched is
			 * being processed only/, because |t| is in
			 * the middle of a desched, which means it's
			 * successfully allocated (but not yet
			 * committed) this syscall record. */
			const struct syscallbuf_record* rec;
		} desched;

		/**
		 * Pseudosignals comprise three types of events: real,
		 * deterministic signals raised by tracee execution
		 * (e.g. tracees executing rdtsc); real signals raised
		 * because of rr implementation details, not the
		 * tracee (e.g., time-slice interrupts); and finally,
		 * "signals" from the recorder to the replayer that
		 * aren't real signals at all, but rather rr
		 * implementation details at the level of the tracer.
		 */
		struct {
			/* TODO: un-gnarl these names when we
			 * eliminate the duplication in trace.h */
			PseudosigType no;
			/* When replaying a pseudosignal is expected
			 * to leave the tracee in the same execution
			 * state as during replay, the event has
			 * meaningful execution info, and it should be
			 * recorded for checking.  But some pseudosigs
			 * aren't recorded in the same tracee state
			 * they'll be replayed, so the tracee
			 * exeuction state isn't meaningful. */
			int has_exec_info;
		} pseudosig;

		/**
		 * Signal events track signals through the delivery
		 * phase, and if the signal finds a sighandler, on to
		 * the end of the handling face.
		 */
		struct {
			/* Signal number. */
			int no;
			/* Nonzero if this signal will be
			 * deterministically raised as the side effect
			 * of retiring an instruction during replay,
			 * for example |load $r 0x0| deterministically
			 * raises SIGSEGV. */
			int deterministic;
			/* Nonzero when this signal has been delivered
			 * by a ptrace() request. */
			int delivered;
		} signal;

		/**
		 * Syscall events track syscalls through entry into
		 * the kernel, processing in the kernel, and exit from
		 * the kernel.
		 */
		struct {
			SyscallState state;
			/* Syscall number. */
			int no;
			/* When tasks enter syscalls that may block
			 * and so must be prepared for a
			 * context-switch, and the syscall params
			 * include (in)outparams that point to
			 * buffers, we need to redirect those
			 * arguments to scratch memory.  This allows
			 * rr to serialize execution of what may be
			 * multiple blocked syscalls completing
			 * "simulatenously" (from rr's perspective).
			 * After the syscall exits, we restore the
			 * data saved in scratch memory to the
			 * original buffers.
			 *
			 * Then during replay, we simply restore the
			 * saved data to the tracee's passed-in buffer
			 * args and continue on.
			 *
			 * The array |saved_arg_ptr| stores the
			 * original callee pointers that we replaced
			 * with pointers into the syscallbuf.
			 * |tmp_data_num_bytes| is the number of bytes
			 * we'll be saving across *all* buffer
			 * outparams.  (We can save one length value
			 * because all the tmp pointers into scratch
			 * are contiguous.)  |tmp_data_ptr| /usually/
			 * points at |scratch_ptr|, except ...
			 *
			 * ... a fly in this ointment is may-block
			 * buffered syscalls.  If a task blocks in one
			 * of those, it will look like it just entered
			 * a syscall that needs a scratch buffer.
			 * However, it's too late at that point to
			 * fudge the syscall args, because processing
			 * of the syscall has already begun in the
			 * kernel.  But that's OK: the syscallbuf code
			 * has already swapped out the original
			 * buffer-pointers for pointers into the
			 * syscallbuf (which acts as its own scratch
			 * memory).  We just have to worry about
			 * setting things up properly for replay.
			 *
			 * The descheduled syscall will "abort" its
			 * commit into the syscallbuf, so the outparam
			 * data won't actually be saved there (and
			 * thus, won't be restored during replay).
			 * During replay, we have to restore them like
			 * we restore the non-buffered-syscall scratch
			 * data.
			 *
			 * What we do is add another level of
			 * indirection to the "scratch pointer",
			 * through |tmp_data_ptr|.  Usually that will
			 * point at |scratch_ptr|, for unbuffered
			 * syscalls.  But for desched'd buffered ones,
			 * it will point at the region of the
			 * syscallbuf that's being used as "scratch".
			 * We'll save that region during recording and
			 * restore it during replay without caring
			 * which scratch space it points to.
			 *
			 * (The recorder code has to be careful,
			 * however, not to attempt to copy-back
			 * syscallbuf tmp data to the "original"
			 * buffers.  The syscallbuf code will do that
			 * itself.) */
			FIXEDSTACK_DECL(, void*, 5) saved_args;
			byte* tmp_data_ptr;
			ssize_t tmp_data_num_bytes;

			/* Nonzero when this syscall was restarted
			 * after a signal interruption. */
			int is_restart;
			/* The original (before scratch is set up)
			 * arguments to the syscall passed by the
			 * tracee.  These are used to detect restarted
			 * syscalls. */
			struct user_regs_struct regs;
			/* If this is a descheduled buffered syscall,
			 * points at the record for that syscall. */
			const struct syscallbuf_record* desched_rec;
		} syscall;
	};
};

enum CloneFlags {
	/**
	 * The child gets a semantic copy of all parent resources (and
	 * becomes a new task group).  This is the semantics of the
	 * fork() syscall.
	 */
	CLONE_SHARE_NOTHING = 0,
	/**
	 * Child will share the table of signal dispositions with its
	 * parent.
	 */
	CLONE_SHARE_SIGHANDLERS = 1 << 0,
	/** Child will join its parent's task group. */
	CLONE_SHARE_TASK_GROUP = 1 << 1,
	/** Child will share its parent's address space. */
	CLONE_SHARE_VM = 1 << 2,
};

/**
 * A "task" is a task in the linux usage: the unit of scheduling.  (OS
 * people sometimes call this a "thread control block".)  Multiple
 * tasks may share the same address space and file descriptors, in
 * which case they're commonly called "threads".  Or two tasks may
 * have their own address spaces and file descriptors, in which case
 * they're called "processes".  Both look the same to rr (on linux),
 * so no distinction is made here.
 */
class Task {
public:
	typedef std::map<pid_t, Task*> Map;
	/** For each priority, the list of tasks with that priority.
	    These lists are never empty. */
	typedef std::set<std::pair<int, Task*> > PrioritySet;

	~Task();

	/**
	 * Return a new Task cloned from this.  |flags| are a set of
	 * CloneFlags (see above) that determine which resources are
	 * shared or copied to the new child.  |new_tid| is the tid
	 * assigned to the new task by the kernel.  |new_rec_tid| is
	 * only relevant to replay, and is the pid that was assigned
	 * to the task during recording.
	 */
	Task* clone(int flags, const byte* stack, pid_t new_tid,
		    pid_t new_rec_tid = -1);

	/**
	 * Shortcut to the single |pending_event->desched.rec| when
	 * there's one desched event on the stack, and NULL otherwise.
	 * Exists just so that clients don't need to dig around in the
	 * event stack to find this record.
	 */
	const struct syscallbuf_record* desched_rec() const;

	/**
	 * Mark the members of this task's group as "unstable",
	 * meaning that even though a task may look runnable, it
	 * actually might not be.  (And so |waitpid(-1)| should be
	 * used to schedule the next task.)
	 *
	 * This is needed to handle the peculiarities of mass Task
	 * death at exit_group() and upon receiving core-dumping
	 * signals.  The reason it's needed is easier to understand if
	 * you keep in mind that the "main loop" of ptrace tracers is
	 * /supposed/ to look like
	 *
	 *   while (true) {
	 *     int tid = waitpid(-1, ...);
	 *     // do something with tid
	 *     ptrace(tid, PTRACE_SYSCALL, ...);
	 *   }
	 *
	 * That is, the tracer is supposed to let the kernel schedule
	 * threads and then respond to notifications generated by the
	 * kernel.
	 *
	 * Obviously this isn't how rr's recorder loop looks, because,
	 * among other things, rr has to serialize thread execution.
	 * Normally this isn't much of a problem.  However, mass task
	 * death is an exception.  What happens at a mass task death
	 * is a sequence of events like the following
	 *
	 *  1. A task calls exit_group() or is sent a core-dumping
	 *     signal.
	 *  2. rr receives a PTRACE_EVENT_EXIT notification for the
	 *     task.
	 *  3. rr detaches from the dying/dead task.
	 *  4. Successive calls to waitpid(-1) generate additional
	 *     PTRACE_EVENT_EXIT notifications for each also-dead task
	 *     in the original task's thread group.  Repeat (2) / (3)
	 *     for each notified task.
	 *
	 * So why destabilization?  After (2), rr can't block on the
	 * task shutting down (|waitpid(tid)|), because the kernel
	 * harvests the LWPs of the dying task group in an unknown
	 * order (which we shouldn't assume, even if we could guess
	 * it).  If rr blocks on the task harvest, it will (usually)
	 * deadlock.
	 *
	 * And because rr doesn't know the order of tasks that will be
	 * reaped, it doesn't know which of the dying tasks to
	 * "schedule".  If it guesses and blocks on another task in
	 * the group's status-change, it will (usually) deadlock.
	 *
	 * So destabilizing a task group, from rr's perspective, means
	 * handing scheduling control back to the kernel and not
	 * trying to harvest tasks before detaching from them.
	 *
	 * NB: an invariant of rr scheduling is that all process
	 * status changes happen as a result of rr resuming the
	 * execution of a task.  This is required to keep tracees in
	 * known states, preventing events from happening "behind rr's
	 * back".  However, destabilizing a task group means that
	 * these kinds of changes are possible, in theory.
	 *
	 * Currently, instability is a one-way street; it's only used
	 * needed for death signals and exit_group().
	 */
	void destabilize_task_group();

	/**
	 * Dump attributes of this process, including pending events,
	 * to |out|, which defaults to LOG_FILE.
	 */
	void dump(FILE* out = NULL) const;

	/**
	 * Sets the priority to 'value', updating the map-by-priority.
	 * Small priority values mean higher priority.
	 */
	void set_priority(int value);

	/**
	 * Stat |fd| in the context of this task's fd table, returning
	 * the result in |buf|.  The name of the referent file is
	 * returned in |buf|, of max size |buf_num_bytes|.  Return
	 * true on success, false on error.
	 */
	bool fdstat(int fd, struct stat* st, char* buf, size_t buf_num_bytes);

	/**
	 * Return nonzero if |t| may not be immediately runnable,
	 * i.e., resuming execution and then |waitpid()|'ing may block
	 * for an unbounded amount of time.  When the task is in this
	 * state, the tracer must await a |waitpid()| notification
	 * that the task is no longer possibly-blocked before resuming
	 * its execution.
	 */
	bool may_be_blocked() const;

	/**
	 * If |syscallno| at |state| changes our VM mapping, then
	 * update the cache for that change.  The exception is mmap()
	 * calls: they're complicated enough to be handled separately.
	 * Client code should call |t->vm()->map(...)| directly.
	 */
	void maybe_update_vm(int syscallno, int state,
			     const struct user_regs_struct& regs);

	/**
	 * Return the "task name"; i.e. what |prctl(PR_GET_NAME)| or
	 * /proc/tid/comm would say that the task's name is.
	 */
	const std::string& name() const { return prname; }

	/**
	 * Call this after an |execve()| syscall finishes.  Emulate
	 * resource updates induced by the exec.
	 */
	void post_exec();

	/**
	 * Return the word at |child_addr| in this address space.
	 *
	 * NB: doesn't use the ptrace API, so safe to use even when
	 * the tracee isn't at a trace-stop.
	 */
	long read_word(byte* child_addr);

	/**
	 * Set the disposition and resethand semantics of |sig| to
	 * |sa|, overwriting whatever may already be there.
	 */
	void set_signal_disposition(int sig,
				    const struct kernel_sigaction& sa);

	/**
	 * Call this after |sig| is delivered to this task.  Emulate
	 * sighandler updates induced by the signal delivery.
	 */
	void signal_delivered(int sig);

	/**
	 * Return nonzero if the disposition of |sig| in |table| isn't SIG_IGN
	 * or SIG_DFL, that is, if a user sighandler will be invoked when
	 * |sig| is received.
	 */
	bool signal_has_user_handler(int sig) const;

	/**
	 * Return the id of this task's thread group.
	 */
	pid_t tgid() const;

	/**
	 * Call this after the tracee successfully makes a
	 * |prctl(PR_SET_NAME)| call to change the task name to the
	 * string pointed at in the tracee's address space by
	 * |child_addr|.
	 */
	void update_prname(byte* child_addr);

	/**
	 * Return the virtual memory mapping (address space) of this
	 * task.
	 */
	AddressSpace::shr_ptr vm() { return as; }

	/**
	 * Write |word| to |child_addr| in this address space.
	 *
	 * NB: doesn't use the ptrace API, so safe to use even when
	 * the tracee isn't at a trace-stop.
	 */
	void write_word(byte* child_addr, long word);

	/** Return an iterator at the beginning of the task map. */
	static Map::const_iterator begin();

	/** Return an iterator at the end of the task map. */
	static Map::const_iterator end();

	/** Return the number of extant tasks. */
	static ssize_t count();

	/** Get tasks organized by priority. */
	static const PrioritySet& get_priority_set();

	/**
	 * Create and return the first tracee task.  It's hard-baked
	 * into rr that the first tracee is fork()ed, so create()
	 * "clones" the new task using fork() semantics.  |tid| and
	 * |rec_tid| are as for Task::clone().
	 */
	static Task* create(pid_t tid, pid_t rec_tid = -1);

	/** Call |Task::dump(out)| for all live tasks. */
	static void dump_all(FILE* out = NULL);

	/**
	 * Return the task created with |rec_tid|, or NULL if no such
	 * task exists.
	 */
	static Task* find(pid_t rec_tid);

	/* State only used during recording. */

	/* The running count of events that have been recorded for
	 * this task.  Starts at "1" to match with "global_time". */
	int thread_time;

	/* For convenience, the current top of |pending_events| if
	 * there are any.  If there aren't any pending, the top of the
	 * stack will be a placeholder event of type EV_SENTINEL.
	 *
	 * Never reassign this pointer directly; use the
	 * push_*()/pop_*() helpers below. */
	/* TODO: make me a helper method */
	struct event* ev;
	/* The current stack of events being processed. */
	FIXEDSTACK_DECL(, struct event, 16) pending_events;

	/* Whether switching away from this task is allowed in its
	 * current state.  Some operations must be completed
	 * atomically and aren't switchable. */
	int switchable;
	/* Number of times this context has been scheduled in a row,
	 * which approximately corresponds to the number of events
	 * it's processed in succession.  The scheduler maintains this
	 * state and uses it to make scheduling decisions. */
	int succ_event_counter;
	/* Nonzero when any assumptions made about the status of this
	 * process have been invalidated, and must be re-established
	 * with a waitpid() call. */
	int unstable;

	/* Task 'nice' value set by setpriority(2).
	   We use this to drive scheduling decisions. rr's scheduler is
	   deliberately simple and unfair; a task never runs as long as there's
	   another runnable task with a lower nice value. */
	int priority;

	/* Imagine that task A passes buffer |b| to the read()
	 * syscall.  Imagine that, after A is switched out for task B,
	 * task B then writes to |b|.  Then B is switched out for A.
	 * Since rr doesn't schedule the kernel code, the result is
	 * nondeterministic.  To avoid that class of replay
	 * divergence, we "redirect" (in)outparams passed to may-block
	 * syscalls, to "scratch memory".  The kernel writes to
	 * scratch deterministically, and when A (in the example
	 * above) exits its read() syscall, rr copies the scratch data
	 * back to the original buffers, serializing A and B in the
	 * example above.
	 *
	 * Syscalls can "nest" due to signal handlers.  If a syscall A
	 * is interrupted by a signal, and the sighandler calls B,
	 * then we can have scratch buffers set up for args of both A
	 * and B.  In linux, B won't actually re-enter A; A is exited
	 * with a "will-restart" error code and its args are saved for
	 * when (or if) it's restarted after the signal.  But that
	 * doesn't really matter wrt scratch space.  (TODO: in the
	 * future, we may be able to use that fact to simplify
	 * things.)
	 *
	 * Because of nesting, at first blush it seems we should push
	 * scratch allocations onto a stack and pop them as syscalls
	 * (or restarts thereof) complete.  But under a critical
	 * assumption, we can actually skip that.  The critical
	 * assumption is that the kernel writes its (in)outparams
	 * atomically wrt signal interruptions, and only writes them
	 * on successful exit.  Each syscall will complete in stack
	 * order, and it's invariant that the syscall processors must
	 * only write back to user buffers *only* the data that was
	 * written by the kernel.  So as long as the atomicity
	 * assumption holds, the completion of syscalls higher in the
	 * event stack may overwrite scratch space, but the completion
	 * of each syscall will overwrite those overwrites again, and
	 * that over-overwritten data is exactly and only what we'll
	 * write back to the tracee.
	 *
	 * |scratch_ptr| points at the mapped address in the child,
	 * and |size| is the total available space. */
	byte* scratch_ptr;
	ssize_t scratch_size;

	int event;
	/* Nonzero after the trace recorder has flushed the
	 * syscallbuf.  When this happens, the recorder must prepare a
	 * "reset" of the buffer, to zero the record count, at the
	 * next available slow (taking |desched| into
	 * consideration). */
	int flushed_syscallbuf;
	/* This bit is set when code wants to prevent the syscall
	 * record buffer from being reset when it normally would be.
	 * Currently, the desched'd syscall code uses this. */
	int delay_syscallbuf_reset;
	/* This bit is set when code wants the syscallbuf to be
	 * "synthetically empty": even if the record counter is
	 * nonzero, it should not be flushed.  Currently, the
	 * desched'd syscall code uses this along with
	 * |delay_syscallbuf_reset| above to keep the syscallbuf
	 * intact during possibly many "reentrant" events. */
	int delay_syscallbuf_flush;

	/* The child's desched counter event fd number, and our local
	 * dup. */
	int desched_fd, desched_fd_child;
	/* True when the tracee has started using the syscallbuf, and
	 * the tracer will start receiving PTRACE_SECCOMP events for
	 * traced syscalls.  We don't make any attempt to guess at the
	 * OS's process/thread semantics; this flag goes on the first
	 * time rr sees a PTRACE_SECCOMP event from the task.
	 *
	 * NB: there must always be at least one traced syscall before
	 * any untraced ones; that's the magic "rrcall" the tracee
	 * uses to initialize its syscallbuf. */
	int seccomp_bpf_enabled;

	/* State used only during replay. */

	int child_sig;

	/* State used during both recording and replay. */

	struct trace_frame trace;
	struct hpc_context* hpc;

	/* The most recent status of this task as returned by
	 * waitpid(). */
	int status;

	struct user_regs_struct regs;
	/* This is always the "real" tid of the tracee. */
	pid_t tid;
	/* This is always the recorded tid of the tracee.  During
	 * recording, it's synonymous with |tid|, and during replay
	 * it's the tid that was recorded. */
	pid_t rec_tid;
	int child_mem_fd;

	/* The instruction pointer from which untraced syscalls will
	 * originate, used to determine whether a syscall is being
	 * made by the syscallbuf wrappers or not. */
	byte* untraced_syscall_ip;
	/* Start and end of the mapping of the syscallbuf code
	 * section, used to determine whether a tracee's $ip is in the
	 * lib. */
	byte* syscallbuf_lib_start;
	byte* syscallbuf_lib_end;
	/* Points at rr's mapping of the (shared) syscall buffer. */
	struct syscallbuf_hdr* syscallbuf_hdr;
	size_t num_syscallbuf_bytes;
	/* Points at the tracee's mapping of the buffer. */
	byte* syscallbuf_child;

private:
	Task(pid_t tid, pid_t rec_tid, int priority);

	/* The address space of this task. */
	std::shared_ptr<AddressSpace> as;
	/* Task's OS name */
	std::string prname;
	/* Points to the signal-hander table of this task.  If this
	 * task is a non-fork clone child, then the table will be
	 * shared with all its "thread" siblings.  Any updates made to
	 * that shared table are immediately visible to all sibling
	 * threads.
	 *
	 * fork and vfork children always get their own copies of the
	 * table.  And if this task exec()s, the table is copied and
	 * stripped of user sighandlers (see below). */
	std::shared_ptr<Sighandlers> sighandlers;
	/* The task group this belongs to. */
	std::shared_ptr<TaskGroup> task_group;

	Task(Task&) = delete;
	Task operator=(Task&) = delete;
};

/* (This function is an implementation detail that should go away in
 * favor of a |task_init()| pseudo-constructor that initializes state
 * shared across record and replay.) */
void push_placeholder_event(Task* t);

/**
 * Push/pop event tracking descheduling of |rec|.
 */
void push_desched(Task* t, const struct syscallbuf_record* rec);
void pop_desched(Task* t);

/**
 * Push/pop pseudo-sig events on the pending stack.  |no| is the enum
 * value of the pseudosig (see above), and |record_exec_info| is true
 * if the tracee's current state can be replicated during replay and
 * so should be recorded for consistency-checking purposes.
 */
enum { NO_EXEC_INFO = 0, HAS_EXEC_INFO };
void push_pseudosig(Task* t, PseudosigType no, int has_exec_info);
void pop_pseudosig(Task* t);

/**
 * Push/pop signal events on the pending stack.  |no| is the signum,
 * and |deterministic| is nonzero for deterministically-delivered
 * signals (see handle_signal.c).
 */
enum { NONDETERMINISTIC_SIG = 0, DETERMINISTIC_SIG = 1 };
void push_pending_signal(Task* t, int no, int deterministic);
void pop_signal_delivery(Task* t);
void pop_signal_handler(Task* t);

/**
 * Push/pop syscall events on the pending stack.  |no| is the syscall
 * number.
 */
void push_syscall(Task* t, int no);
void pop_syscall(Task* t);

/**
 * Push/pop syscall interruption events.
 *
 * During recording, only descheduled buffered syscalls /push/ syscall
 * interruptions; all others are detected at exit time and transformed
 * into syscall interruptions from the original, normal syscalls.
 *
 * During replay, we push interruptions to know when we need to
 * emulate syscall entry, since the kernel won't have set things up
 * for the tracee to restart on its own.
 */
void push_syscall_interruption(Task* t, int no,
			       const struct user_regs_struct* args);
void pop_syscall_interruption(Task* t);

/**
 * Dump |t|'s stack of pending events to INFO log.
 */
void log_pending_events(const Task* t);

/**
 * Dump info about |ev| to INFO log.
 */
void log_event(const struct event* ev);

/**
 * Return a string naming |ev|'s type.
 */
const char* event_name(const struct event* ev);

#endif /* TASK_H_ */
