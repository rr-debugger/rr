/* -*- Mode: C++; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

//#define DEBUGTAG "Task"

#include "task.h"

#include <errno.h>
#include <linux/kdev_t.h>
#include <linux/net.h>
#include <stdlib.h>
#include <string.h>
#include <syscall.h>
#include <sys/personality.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <limits>
#include <set>

#include "preload/syscall_buffer.h"

#include "hpc.h"
#include "log.h"
#include "session.h"
#include "util.h"

#define NUM_X86_DEBUG_REGS 8
#define NUM_X86_WATCHPOINTS 4

using namespace std;

/*static*/ const byte AddressSpace::breakpoint_insn;

/**
 * Format into |path| the path name at which syscallbuf shmem for
 * tracee |tid| will be allocated (briefly, until unlinked).
 */
template<size_t N>
void format_syscallbuf_shmem_path(pid_t tid, char (&path)[N])
{
	static int nonce;
	snprintf(path, N - 1, SYSCALLBUF_SHMEM_NAME_PREFIX "%d-%d",
		 tid, nonce++);
}

// TODO: merge other dups of this function.
static void write_socketcall_args(Task* t,
				  struct socketcall_args* child_args_vec,
				  long arg1, long arg2, long arg3)
{
	struct socketcall_args args = { { arg1, arg2, arg3 } };
	t->write_mem(child_args_vec, args);
}

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
	case PSEUDODEVICE_SHARED_MMAP_FILE: return "(shmmap)";
	case PSEUDODEVICE_STACK: return "(stack)";
	case PSEUDODEVICE_SYSCALLBUF: return "(syscallbuf)";
	case PSEUDODEVICE_VDSO: return "(vdso)";
	}
	FATAL() <<"Not reached";
	return nullptr;
}

void
HasTaskSet::insert_task(Task* t)
{
	LOG(debug) <<"adding "<< t->tid <<" to task set "<< this;
	tasks.insert(t);
}

void
HasTaskSet::erase_task(Task* t) {
	LOG(debug) <<"removing "<< t->tid <<" from task group "<< this;
	tasks.erase(t);
}

FileId::FileId(dev_t dev_major, dev_t dev_minor, ino_t ino, PseudoDevice psdev)
	: device(MKDEV(dev_major, dev_minor)), inode(ino)
	, psdev(psdev) { }

ostream& operator<<(ostream& o, const Mapping& m)
{
	o << m.start <<"-"<< m.end <<" "<< HEX(m.prot) <<" f:"<< HEX(m.flags);
	return o;
}

/*static*/ MappableResource
MappableResource::shared_mmap_file(const struct mmapped_file& file)
{
	return MappableResource(
		FileId(file.stat, PSEUDODEVICE_SHARED_MMAP_FILE),
		file.filename);
}

/*static*/ MappableResource
MappableResource::syscallbuf(pid_t tid, int fd, const char* path)
 {
	 struct stat st;
	 if (fstat(fd, &st)) {
		 FATAL() <<"Failed to fstat("<< fd <<") ("<< path <<")";
	 }
	 return MappableResource(FileId(st), path);
 }

/**
 * Represents a refcount set on a particular address.  Because there
 * can be multiple refcounts of multiple types set on a single
 * address, Breakpoint stores explicit USER and INTERNAL breakpoint
 * refcounts.  Clients adding/removing breakpoints at this addr must
 * call ref()/unref() as appropropiate.
 */
struct Breakpoint {
	typedef shared_ptr<Breakpoint> shr_ptr;

	// AddressSpace::destroy_all_breakpoints() can cause this
	// destructor to be invoked while we have nonzero total
	// refcount, so the most we can assert is that the refcounts
	// are valid.
	~Breakpoint() { assert(internal_count >= 0 && user_count >= 0); }

	shr_ptr clone() {
		return shr_ptr(new Breakpoint(*this));
	}

	void ref(TrapType which) {
		assert(internal_count >= 0 && user_count >= 0);
		++*counter(which);
	}
	int unref(TrapType which) {
		assert(internal_count >= 0 && user_count >= 0
		       && (internal_count > 0 || user_count > 0));
		--*counter(which);
		return internal_count + user_count;
	}

	TrapType type() const {
		// NB: USER breakpoints need to be processed before
		// INTERNAL ones.  We want to give the debugger a
		// chance to dispatch commands before we attend to the
		// internal rr business.  So if there's a USER "ref"
		// on the breakpoint, treat it as a USER breakpoint.
		return user_count > 0 ? TRAP_BKPT_USER : TRAP_BKPT_INTERNAL;
	}

	static shr_ptr create() {
		return shr_ptr(new Breakpoint());
	}

	// "Refcounts" of breakpoints set at |addr|.  The breakpoint
	// object must be unique since we have to save the overwritten
	// data, and we can't enforce the order in which breakpoints
	// are set/removed.
	int internal_count, user_count;
	byte overwritten_data;
	static_assert(sizeof(overwritten_data) ==
		      sizeof(AddressSpace::breakpoint_insn), 
		      "Must have the same size.");
private:
	Breakpoint() : internal_count(), user_count() { }
	Breakpoint(const Breakpoint& o) = default;

	int* counter(TrapType which) {
		assert(TRAP_BKPT_INTERNAL == which || TRAP_BKPT_USER == which);
		int* p = TRAP_BKPT_USER == which ?
			 &user_count : &internal_count;
		assert(*p >= 0);
		return p;
	}
};

enum {
	EXEC_BIT = 1 << 0, READ_BIT = 1 << 1, WRITE_BIT = 1 << 2
};

/** Return the access bits above needed to watch |type|. */
static int access_bits_of(WatchType type)
{
	switch (type) {
	case WATCH_EXEC:
		return EXEC_BIT;
	case WATCH_WRITE:
		return WRITE_BIT;
	case WATCH_READWRITE:
		return READ_BIT | WRITE_BIT;
	default:
		FATAL() <<"Unknown watchpoint type "<< type;
		return 0;	// not reached
	}
}

/**
 * Track the watched accesses of a contiguous range of memory
 * addresses.
 */
class Watchpoint {
public:
	typedef shared_ptr<Watchpoint> shr_ptr;

	~Watchpoint() { assert_valid(); }

	shr_ptr clone() { return shr_ptr(new Watchpoint(*this)); }

	void watch(int which) {
		assert_valid();
		exec_count += (EXEC_BIT & which);
		read_count += (READ_BIT & which);
		write_count += (WRITE_BIT & which);
	}
	int unwatch(int which) {
		assert_valid();
		if (EXEC_BIT & which) {
			assert(exec_count > 0);
			--exec_count;
		}
		if (READ_BIT & which) {
			assert(read_count > 0);
			--read_count;
		}
		if (WRITE_BIT & which) {
			assert(write_count > 0);
			--write_count;
		}
		return exec_count + read_count + write_count;
	}

	int watched_bits() const {
		return (exec_count > 0 ? EXEC_BIT : 0)
			| (read_count > 0 ? READ_BIT : 0)
			| (write_count > 0 ? WRITE_BIT : 0);
	}

	static shr_ptr create() {
		return shr_ptr(new Watchpoint());
	}

private:
	Watchpoint() : exec_count(), read_count(), write_count() { }
	Watchpoint(const Watchpoint&) = default;

	void assert_valid() const {
		assert(exec_count >= 0 && read_count >= 0 && write_count >= 0);
	}

	// Watchpoints stay alive until all watched access typed have
	// been cleared.  We track refcounts of each watchable access
	// separately.
	int exec_count, read_count, write_count;
};

AddressSpace::~AddressSpace()
{
	session->on_destroy(this);
}

void
AddressSpace::after_clone()
{
	allocate_watchpoints();
}

void
AddressSpace::brk(void* addr)
{
	LOG(debug) << "brk("<< addr <<")";

	assert(heap.start <= addr);
	if (addr == heap.end) {
		return;
	}

	update_heap(heap.start, addr);
	map(heap.start, heap.num_bytes(), heap.prot, heap.flags, heap.offset,
	    MappableResource::heap());
}

void
AddressSpace::dump() const
{
	fprintf(stderr, "  (heap: %p-%p)\n", heap.start, heap.end);
	for (auto it = mem.begin(); it != mem.end(); ++it) {
		const Mapping& m = it->first;
		const MappableResource& r = it->second;
		fprintf(stderr, "%s %s\n", m.str().c_str(),
				r.str().c_str());
	}
}

TrapType
AddressSpace::get_breakpoint_type_at_ip(void* ip)
{
	void* addr = (byte*)ip - sizeof(breakpoint_insn);
	auto it = breakpoints.find(addr);
	return it == breakpoints.end() ? TRAP_NONE : it->second->type();
}

void
AddressSpace::map(void* addr, size_t num_bytes, int prot, int flags,
		  off64_t offset_bytes, const MappableResource& res)
{
	LOG(debug) <<"mmap("<< addr <<", "<< num_bytes <<", "<< HEX(prot)
		   <<", "<< HEX(flags) <<", "<< HEX(offset_bytes);

	num_bytes = ceil_page_size(num_bytes);

	Mapping m(addr, num_bytes, prot, flags, offset_bytes);
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
AddressSpace::mapping_of(void* addr, size_t num_bytes) const
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
static off64_t adjust_offset(const MappableResource& r, const Mapping& m,
			     off64_t delta)
{
	return r.id.is_real_device() ? m.offset + delta : 0;
}

void
AddressSpace::protect(void* addr, size_t num_bytes, int prot)
{
	LOG(debug) <<"mprotect("<< addr <<", "<< num_bytes <<", "<< HEX(prot) <<")";

	Mapping last_overlap;
	auto protector = [this, prot, &last_overlap](
		const Mapping& m, const MappableResource& r,
		const Mapping& rem) {
		LOG(debug) <<"  protecting ("<< rem <<") ...";

		mem.erase(m);
		LOG(debug) <<"  erased ("<< m <<")";

		// If the first segment we protect underflows the
		// region, remap the underflow region with previous
		// prot.
		if (m.start < rem.start) {
			Mapping underflow(m.start, rem.start, m.prot, m.flags,
					  m.offset);
			mem[underflow] = r;
		}
		// Remap the overlapping region with the new prot.
		void* new_end = min(rem.end, m.end);
		Mapping overlap(rem.start, new_end, prot, m.flags,
				adjust_offset(r, m,
					      (byte*)rem.start - (byte*)m.start));
		mem[overlap] = r;
		last_overlap = overlap;

		// If the last segment we protect overflows the
		// region, remap the overflow region with previous
		// prot.
		if (rem.end < m.end) {
			Mapping overflow(rem.end, m.end, m.prot, m.flags,
					 adjust_offset(r, m,
						       (byte*)rem.end - (byte*)m.start));
			mem[overflow] = r;
		}
	};
	for_each_in_range(addr, num_bytes, protector, ITERATE_CONTIGUOUS);
	// All mappings that we altered which might need coalescing
	// are adjacent to |last_overlap|.
	coalesce_around(mem.find(last_overlap));
}

void
AddressSpace::remap(void* old_addr, size_t old_num_bytes,
		    void* new_addr, size_t new_num_bytes)
{
	LOG(debug) <<"mremap("<< old_addr <<", "<< old_num_bytes <<", "
		   << new_addr <<", "<< new_num_bytes <<")";

	auto mr = mapping_of(old_addr, old_num_bytes);
	const Mapping& m = mr.first;
	const MappableResource& r = mr.second;

	unmap(old_addr, old_num_bytes);
	if (0 == new_num_bytes) {
		return;
	}

	map_and_coalesce(Mapping((byte*)new_addr, new_num_bytes,
				 m.prot, m.flags,
				 adjust_offset(r, m,
					       ((byte*)old_addr - (byte*)m.start))),
			 r);
}

void
AddressSpace::remove_breakpoint(void* addr, TrapType type)
{
	auto it = breakpoints.find(addr);
	if (it == breakpoints.end() || !it->second
	    || it->second->unref(type) > 0) {
		return;
	}
	destroy_breakpoint(it);
}

bool
AddressSpace::set_breakpoint(void* addr, TrapType type)
{
	auto it = breakpoints.find(addr);
	if (it == breakpoints.end()) {
		auto bp = Breakpoint::create();
		// Grab a random task from the VM so we can use its
		// read/write_mem() helpers.
		Task* t = *task_set().begin();
		if (sizeof(bp->overwritten_data) !=
		    t->read_bytes_fallible(addr,
					   sizeof(bp->overwritten_data),
					   &bp->overwritten_data)) {
			return false;
		}
		t->write_mem(addr, breakpoint_insn);

		auto it_and_is_new = breakpoints.insert(make_pair(addr, bp));
		assert(it_and_is_new.second);
		it = it_and_is_new.first;
	}
	it->second->ref(type);
	return true;
}

void
AddressSpace::destroy_all_breakpoints()
{
	while (!breakpoints.empty()) {
		destroy_breakpoint(breakpoints.begin());
	}
}

void
AddressSpace::remove_watchpoint(void* addr, size_t num_bytes, WatchType type)
{
	auto it = watchpoints.find(MemoryRange(addr, num_bytes));
	if (it != watchpoints.end()
	    && 0 == it->second->unwatch(access_bits_of(type))) {
		watchpoints.erase(it);
	}
	allocate_watchpoints();
}

bool
AddressSpace::set_watchpoint(void* addr, size_t num_bytes, WatchType type)
{
	MemoryRange key(addr, num_bytes);
	auto it = watchpoints.find(key);
	if (it == watchpoints.end()) {
		auto it_and_is_new =
			watchpoints.insert(make_pair(key,
						     Watchpoint::create()));
		assert(it_and_is_new.second);
		it = it_and_is_new.first;
	}
	it->second->watch(access_bits_of(type));
	return allocate_watchpoints();
}

void
AddressSpace::destroy_all_watchpoints()
{
	watchpoints.clear();
	allocate_watchpoints();
}

void
AddressSpace::unmap(void* addr, ssize_t num_bytes)
{
	LOG(debug) <<"munmap("<< addr <<", "<< num_bytes <<")";

	auto unmapper = [this](const Mapping& m, const MappableResource& r,
			       const Mapping& rem) {
		LOG(debug) <<"  unmapping ("<< rem <<") ...";

		mem.erase(m);
		LOG(debug) <<"  erased ("<< m <<") ...";

		// If the first segment we unmap underflows the unmap
		// region, remap the underflow region.
		if (m.start < rem.start) {
			Mapping underflow(m.start, rem.start, m.prot, m.flags,
					  m.offset);
			mem[underflow] = r;
		}
		// If the last segment we unmap overflows the unmap
		// region, remap the overflow region.
		if (rem.end < m.end) {
			Mapping overflow(rem.end, m.end, m.prot, m.flags,
					 adjust_offset(r, m,
						       (byte*)rem.end - (byte*)m.start));
			mem[overflow] = r;
		}
	};
	for_each_in_range(addr, num_bytes, unmapper);
}

/**
 * Return true iff |left| and |right| are located adjacently in memory
 * with the same metadata, and map adjacent locations of the same
 * underlying (real) device.
 */
static bool is_adjacent_mapping(const MappingResourcePair& left,
				const MappingResourcePair& right)
{
	const Mapping& mleft = left.first;
	const Mapping& mright = right.first;
	if (mleft.end != mright.start) {
		LOG(debug) <<"    (not adjacent in memory)";
		return false;
	}
	if (mleft.flags != mright.flags || mleft.prot != mright.prot) {
		LOG(debug) <<"    (flags or prot differ)";
		return false;
	}
	const MappableResource& rleft = left.second;
	const MappableResource& rright = right.second;
	if (rright.fsname.substr(0, strlen(PREFIX_FOR_EMPTY_MMAPED_REGIONS)) ==
	    PREFIX_FOR_EMPTY_MMAPED_REGIONS) {
		return true;
	}
	if (rleft != rright) {
		LOG(debug) <<"    (not the same resource)";
		return false;
	}
	if (rleft.id.is_real_device()
	    && mleft.offset + mleft.num_bytes() != mright.offset) {
		LOG(debug) <<"    ("<< mleft.offset <<" + "
			   << mleft.num_bytes() <<" != "<< mright.offset
			   <<": offsets into real device aren't adjacent)";
		return false;
	}
	LOG(debug) <<"    adjacent!";
	return true;
}

/**
 * If (*left_m, left_r), (right_m, right_r) are adjacent (see
 * |is_adjacent_mapping()|), write a merged segment descriptor to
 * |*left_m| and return true.  Otherwise return false.
 */
static bool try_merge_adjacent(Mapping* left_m,
			       const MappableResource& left_r,
			       const Mapping& right_m,
			       const MappableResource& right_r)
{
	if (is_adjacent_mapping(MappingResourcePair(*left_m, left_r),
				MappingResourcePair(right_m, right_r))) {
		*left_m = Mapping(left_m->start, right_m.end,
				  right_m.prot, right_m.flags,
				  left_m->offset);
		return true;
	}
	return false;
}

/**
 * Iterate over /proc/maps segments for a task and verify that the
 * task's cached mapping matches the kernel's (given a lenient fuzz
 * factor).
 */
struct VerifyAddressSpace {
	typedef AddressSpace::MemoryMap::const_iterator const_iterator;

	VerifyAddressSpace(const AddressSpace* as)
		: as(as), it(as->mem.begin()), phase(NO_PHASE) { }

	/**
	 * |km| and |m| are the same mapping of the same resource, or
	 * don't return.
	 */
	void assert_segments_match(Task* t);

	/* Current kernel Mapping we're merging and trying to
	 * match. */
	Mapping km;
	/* Current cached Mapping we've merged and are trying to
	 * match. */
	Mapping m;
	/* The resource that |km| and |m| map. */
	MappableResource r;
	const AddressSpace* as;
	/* Iterator over mappings in |as|. */
	const_iterator it;
	/* Which mapping-checking phase we're in.  See below. */
	enum {
		NO_PHASE, MERGING_CACHED, INITING_KERNEL, MERGING_KERNEL
	} phase;
};

void
VerifyAddressSpace::assert_segments_match(Task* t)
{
	assert(MERGING_KERNEL == phase);
	bool same_mapping = (m.start == km.start && m.end == km.end
			     && m.prot == km.prot
			     && m.flags == km.flags);
	if (!same_mapping) {
		LOG(error) <<"cached mmap:";
		as->dump();
		LOG(error) <<"/proc/"<< t->tid <<"/mmaps:";
		print_process_mmap(t);

		ASSERT(t, same_mapping)
			<< "\nCached mapping "<< m <<"should be "<< km;
	}
}

/**
 * Iterate over the segments that are parsed from
 * |/proc/[t->tid]/maps| and ensure that they match up with the cached
 * segments for |t|.
 *
 * This implementation does the following
 *  1. Merge as many adjacent cached mappings as it can.
 *  2. Merge as many adjacent /proc/maps mappings as it can.
 *  3. Ensure that the two merged mappings are the same.
 *  4. Move on to the next mapping region, goto 1.
 *
 * There are two subtleties of this implementation.  The first is that
 * the kernel and rr have (only very slightly! argh) different
 * heuristics for merging adjacent memory mappings.  That means we
 * can't simply iterate through /proc/maps and assert that a cached
 * mapping corresponds to it, though we sure would like to.  Instead,
 * we reduce the rr mappings to the lowest common denonminator that
 * can be parsed from /proc/maps, and assume that adjacent mappings
 * should be merged if they're equal per common lax criteria (i.e.,
 * not honoring either rr or kernel criteria).  That means that the
 * mapped segments that this helper compares may look nothing like the
 * segments you would see in a /proc/maps dump or |as->dump()|.
 *
 * The second subtlety is that rr's /proc/maps iterator uses a C-style
 * callback iterator, whereas the cached map iterator uses a C++
 * iterator in a loop.  That means we have to do a bit of fancy
 * footwork to make the two styles iterate over the same mappings.
 * Since C++ iterators are more flexible, we do the C++ iteration
 * first, and then force a state machine to make the matchin required
 * C-iterator calls.
 *
 * TODO: replace iterate_memory_map()
 */
/*static*/ int
AddressSpace::check_segment_iterator(void* pvas, Task* t,
				     const struct map_iterator_data* data)
{
	VerifyAddressSpace* vas = static_cast<VerifyAddressSpace*>(pvas);
	const AddressSpace* as = vas->as;
	const struct mapped_segment_info& info = data->info;

	LOG(debug) <<"examining /proc/maps segment "<< info;

	// Merge adjacent cached mappings.
	if (vas->NO_PHASE == vas->phase) {
		assert(vas->it != as->mem.end());

		vas->phase = vas->MERGING_CACHED;
		// Start of next segment range to match.
		vas->m = vas->it->first.to_kernel();
		vas->r = vas->it->second.to_kernel();
		do {
			++vas->it;
		} while (vas->it != as->mem.end()
			 && try_merge_adjacent(&vas->m, vas->r,
					       vas->it->first.to_kernel(),
					       vas->it->second.to_kernel()));
		vas->phase = vas->INITING_KERNEL;
	}

	LOG(debug) <<"  merged cached seg: "<< vas->m;

	// Merge adjacent kernel mappings.
	assert(info.flags == (info.flags & Mapping::checkable_flags_mask));
	Mapping km(info.start_addr, info.end_addr, info.prot, info.flags,
		   info.file_offset);
	MappableResource kr(FileId(info.dev_major, info.dev_minor,
				   info.inode), info.name);

	if (vas->INITING_KERNEL == vas->phase) {
		assert(kr == vas->r
		       // XXX not-so-pretty hack.  If the mapped file
		       // lives in our replayer's emulated fs, then it
		       // will have a real system device/inode
		       // descriptor.  We /could/ initialize the
		       // MappableResource with that descriptor, but
		       // we rely on quick access to the recorded
		       // (i.e. emulated in replay) device/inode for
		       // gc.  So this suffices for now.
		       || string::npos != kr.fsname.find(SHMEM_FS "/rr-emufs")
		       || string::npos != kr.fsname.find(SHMEM_FS2 "/rr-emufs"));
		vas->km = km;
		vas->phase = vas->MERGING_KERNEL;
		return CONTINUE_ITERATING;
	}
	if (vas->MERGING_KERNEL == vas->phase
	    && try_merge_adjacent(&vas->km, vas->r, km, kr)) {
		return CONTINUE_ITERATING;
	}

	// Merged as much as we can ... now the mappings must be
	// equal.
	vas->assert_segments_match(t);

	vas->phase = vas->NO_PHASE;
	return check_segment_iterator(pvas, t, data);
}

Mapping
AddressSpace::vdso() const
{
	assert(vdso_start_addr);
	return mapping_of(vdso_start_addr, 1).first;
}

void
AddressSpace::verify(Task* t) const
{
	assert(task_set().end() != task_set().find(t));

	VerifyAddressSpace vas(this);
	iterate_memory_map(t, check_segment_iterator, &vas,
			   kNeverReadSegment, NULL);

	assert(vas.MERGING_KERNEL == vas.phase);
	vas.assert_segments_match(t);
}

AddressSpace::AddressSpace(Task* t, const string& exe, Session& session)
	: exe(exe), is_clone(false), session(&session), vdso_start_addr()
{
	// TODO: this is a workaround of
	// https://github.com/mozilla/rr/issues/1113 .
	if (session.can_validate()) {
		iterate_memory_map(t, populate_address_space, this,
				   kNeverReadSegment, NULL);
		assert(vdso_start_addr);
	}
}

AddressSpace::AddressSpace(const AddressSpace& o)
	// Whether the new VM wants our breakpoints our not,
	// it's going to inherit them.  This is pretty much
	// never what anyone wants, so a call to
	// |remove_all_breakpoints()| is expected soon after
	// the creation of this.
	: breakpoints(o.breakpoints)
	, exe(o.exe), heap(o.heap), is_clone(true)
	, mem(o.mem), session(nullptr)
	, vdso_start_addr(o.vdso_start_addr)
{
	for (auto it = breakpoints.begin(); it != breakpoints.end(); ++it) {
		it->second = it->second->clone();
	}
}

bool
AddressSpace::allocate_watchpoints()
{
	Task::DebugRegs regs;
	for (auto kv : watchpoints) {
		const MemoryRange& r = kv.first;
		int watching = kv.second->watched_bits();
		if (EXEC_BIT & watching) {
			regs.push_back(WatchConfig(r.addr, r.num_bytes,
						   WATCH_EXEC));
		}
		if (!(READ_BIT & watching) && (WRITE_BIT & watching)) {
			regs.push_back(WatchConfig(r.addr, r.num_bytes,
						   WATCH_WRITE));
		}
		if (READ_BIT & watching) {
			regs.push_back(WatchConfig(r.addr, r.num_bytes,
						   WATCH_READWRITE));
		}
	}
	for (auto t : task_set()) {
		if (!t->set_debug_regs(regs)) {
			return false;
		}
	}
	return true;
}

void
AddressSpace::coalesce_around(MemoryMap::iterator it)
{
	Mapping m = it->first;
	MappableResource r = it->second;

	auto first_kv = it;
	while (mem.begin() != first_kv) {
		auto next = first_kv;
		if (!is_adjacent_mapping(*--first_kv, *next)) {
			first_kv = next;
			break;
		}
	}
	auto last_kv = it;
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
		LOG(debug) <<"  no mappings to coalesce";
		return;
	}

	Mapping c(first_kv->first.start, last_kv->first.end, m.prot, m.flags,
		  first_kv->first.offset);
	LOG(debug) <<"  coalescing "<< c;

	mem.erase(first_kv, ++last_kv);

	auto ins = mem.insert(MemoryMap::value_type(c, r));
	assert(ins.second);	// key didn't already exist
}

void
AddressSpace::destroy_breakpoint(BreakpointMap::const_iterator it)
{
	Task* t = *task_set().begin();
	t->write_mem(it->first, it->second->overwritten_data);
	breakpoints.erase(it);
}

void
AddressSpace::for_each_in_range(void* addr, ssize_t num_bytes,
				function<void (const Mapping& m,
					       const MappableResource& r,
					       const Mapping& rem)> f,
				int how)
{
	num_bytes = ceil_page_size(num_bytes);
	byte* last_unmapped_end = (byte*)addr;
	byte* region_end = (byte*)addr + num_bytes;
	while (last_unmapped_end < region_end) {
		// Invariant: |rem| is always exactly the region of
		// memory remaining to be examined for pages to be
		// unmapped.
		Mapping rem(last_unmapped_end, region_end);

		// The next page to iterate may not be contiguous with
		// the last one seen.
		auto it = mem.lower_bound(rem);
		if (mem.end() == it) {
			LOG(debug) <<"  not found, done.";
			return;
		}

		Mapping m = it->first;
		if (rem.end <= m.start) {
			LOG(debug) <<"  mapping at "<< m.start
				   <<" out of range, done.";
			return;
		}
		if (ITERATE_CONTIGUOUS == how &&
		    !(m.start < addr || rem.start == m.start)) {
			LOG(debug) <<"  discontiguous mapping at "<< m.start
				   <<", done.";
			return;
		}

		MappableResource r = it->second;
		f(m, r, rem);

		// Maintain the loop invariant.
		last_unmapped_end = (byte*)m.end;
	}
}

void
AddressSpace::map_and_coalesce(const Mapping& m, const MappableResource& r)
{
	LOG(debug) <<"  mapping "<< m;

	auto ins = mem.insert(MemoryMap::value_type(m, r));
	assert(ins.second);	// key didn't already exist
	coalesce_around(ins.first);
}

/*static*/ int
AddressSpace::populate_address_space(void* asp, Task* t,
				     const struct map_iterator_data* data)
{
	AddressSpace* as = static_cast<AddressSpace*>(asp);
	const struct mapped_segment_info& info = data->info;

	if (!as->heap.start
	    && as->exe == info.name
	    && !(info.prot & PROT_EXEC)
	    && (info.prot & (PROT_READ | PROT_WRITE))) {
		as->update_heap(info.end_addr, info.end_addr);
		LOG(debug) <<"  guessing heap starts at "<< as->heap.start
			   <<" (end of text segment)";
	}

	bool is_dynamic_heap = !strcmp("[heap]", info.name);
	// This segment is adjacent to our previous guess at the start
	// of the dynamic heap, but it's still not an explicit heap
	// segment.  Update the guess.
	if (as->heap.end == info.start_addr && !(info.prot & PROT_EXEC)) {
		assert(as->heap.start == as->heap.end);
		as->update_heap(info.end_addr, info.end_addr);
		LOG(debug) <<"  updating start-of-heap guess to "
			   << as->heap.start <<" (end of mapped-data segment)";
	}

	FileId id;
	if (is_dynamic_heap) {
		id.psdev = PSEUDODEVICE_HEAP;
		as->update_heap(as->heap.start, info.end_addr);
	} else if (!strcmp("[stack]", info.name)) {
		id.psdev = PSEUDODEVICE_STACK;
	} else if (!strcmp("[vdso]", info.name)) {
		assert(!as->vdso_start_addr);
		as->vdso_start_addr = info.start_addr;
		id.psdev = PSEUDODEVICE_VDSO;
	} else {
		id = FileId(MKDEV(info.dev_major, info.dev_minor), info.inode);
	}

	as->map(info.start_addr, (byte*)info.end_addr - (byte*)info.start_addr,
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
	Sighandler() : sa(), resethand() { }
	Sighandler(const struct kernel_sigaction& sa)
		: sa(sa), resethand(sa.sa_flags & SA_RESETHAND) { }

	bool ignored(int sig) const {
		return (SIG_IGN == sa.k_sa_handler ||
			(SIG_DFL == sa.k_sa_handler
			 && IGNORE == default_action(sig)));
	}
	bool is_default() const {
		return SIG_DFL == sa.k_sa_handler && !resethand;
	}
	bool is_user_handler() const {
		static_assert((void*)1 == SIG_IGN, "");
		return (uintptr_t)sa.k_sa_handler & ~(uintptr_t)SIG_IGN;
	}

	kernel_sigaction sa;
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

void
TaskGroup::destabilize()
{
	LOG(debug) <<"destabilizing task group "<< tgid;
	for (auto it = task_set().begin(); it != task_set().end(); ++it) {
		Task* t = *it;
		t->unstable = 1;
		LOG(debug) <<"  destabilized task "<< t->tid;
	}
}

TaskGroup::TaskGroup(pid_t tgid, pid_t real_tgid)
	: tgid(tgid), real_tgid(real_tgid)
{
	LOG(debug) <<"creating new task group "<< tgid <<" (real tgid:"
		   << real_tgid <<")";
}

Task::Task(pid_t _tid, pid_t _rec_tid, int _priority)
	: thread_time(1)
	, switchable(), pseudo_blocked(), succ_event_counter(), unstable()
	, priority(_priority)
	, scratch_ptr(), scratch_size()
	, flushed_syscallbuf()
	, delay_syscallbuf_reset(), delay_syscallbuf_flush()
	  // These will be initialized when the syscall buffer is.
	, desched_fd(-1), desched_fd_child(-1)
	, seccomp_bpf_enabled()
	, child_sig(), stepped_into_syscall()
	, trace(), hpc()
	, tid(_tid), rec_tid(_rec_tid > 0 ? _rec_tid : _tid)
	, untraced_syscall_ip(), syscallbuf_lib_start(), syscallbuf_lib_end()
	, syscallbuf_hdr(), num_syscallbuf_bytes(), syscallbuf_child()
	, blocked_sigs()
	, child_mem_fd(open_mem_fd())
	, prname("???")
	, rbc_boost(0), rbc_slop(0)
	, registers(), registers_known(false)
	, robust_futex_list(), robust_futex_list_len()
	, session_record(nullptr), session_replay(nullptr)
	, stashed_si(), stashed_wait_status()
	, thread_area(), thread_area_valid()
	, tid_futex()
	, top_of_stack()
	, wait_status()
{
	if (RECORD != rr_flags()->option) {
		// This flag isn't meaningful outside recording.
		// Suppress output related to it outside recording.
		switchable = 1;
	}

	push_event(Event(EV_SENTINEL, NO_EXEC_INFO));

	init_hpc(this);
}

Task::~Task()
{
	LOG(debug) <<"task "<< tid <<" (rec:"<< rec_tid <<") is dying ...";

	assert(this == session().find_task(rec_tid));
	// We expect tasks to usually exit by a call to exit() or
	// exit_group(), so it's not helpful to warn about that.
	if (EV_SENTINEL != ev().type()
	    && (pending_events.size() > 2
		|| !(ev().type() == EV_SYSCALL
		     && (SYS_exit == ev().Syscall().no
			 || SYS_exit_group == ev().Syscall().no)))) {
		LOG(warn) << tid <<" still has pending events.  From top down:";
		log_pending_events();
	}

	session().on_destroy(this);
	tg->erase_task(this);
	as->erase_task(this);

	destroy_hpc(this);
	destroy_local_buffers();

	// We need the mem_fd in detach_and_reap().
	detach_and_reap();
	close(child_mem_fd);

	LOG(debug) <<"  dead";
}

bool
Task::at_may_restart_syscall() const
{
	ssize_t depth = pending_events.size();
	const Event* prev_ev =
		depth > 2 ? &pending_events[depth - 2] : nullptr;
	return EV_SYSCALL_INTERRUPTION == ev().type()
		|| (EV_SIGNAL_DELIVERY == ev().type()
		    && prev_ev && EV_SYSCALL_INTERRUPTION == prev_ev->type());
}

void
Task::finish_emulated_syscall()
{
	// XXX verify that this can't be interrupted by a breakpoint trap
	Registers r = regs();
	// TODO: this will execute the instruction just after syscall
	// entry twice, so if that instruction has non-idempotent side
	// effects, replay can diverge.
	cont_sysemu_singlestep();
	set_regs(r);

	force_status(0);
}

const struct syscallbuf_record*
Task::desched_rec() const
{
	return (ev().is_syscall_event() ? ev().Syscall().desched_rec :
		(EV_DESCHED == ev().type()) ? ev().Desched().rec : nullptr);
}

/**
 * In recording, Task is notified of a destabilizing signal event
 * *after* it's been recorded, at the next trace-event-time.  In
 * replay though we're notified at the occurrence of the signal.  So
 * to display the same event time in logging across record/replay,
 * apply this offset.
 */
static int signal_delivery_event_offset()
{
	return RECORD == rr_flags()->option ? -1 : 0;
}

void
Task::destabilize_task_group()
{
	// Only print this helper warning if there's (probably) a
	// human around to see it.  This is done to avoid polluting
	// output from tests.
	if (EV_SIGNAL_DELIVERY == ev().type() && !probably_not_interactive()) {
		printf("[rr.%d] Warning: task %d (process %d) dying from fatal signal %s.\n",
		       trace_time() + signal_delivery_event_offset(),
		       rec_tid, tgid(), signalname(ev().Signal().no));
	}

	tg->destabilize();
}

void
Task::dump(FILE* out) const
{
	out = out ? out : stderr;
	fprintf(out, "  %s(tid:%d rec_tid:%d status:0x%x%s%s)<%p>\n",
		prname.c_str(), tid, rec_tid, wait_status,
		switchable ? "" : " UNSWITCHABLE",
		unstable ? " UNSTABLE" : "",
		this);
	if (RECORD == rr_flags()->option) {
		// TODO pending events are currently only meaningful
		// during recording.  We should change that
		// eventually, to have more informative output.
		log_pending_events();
	}
}

int64_t
Task::effective_rbc() const
{
	int64_t rbc_now = hpc->started ? read_rbc(hpc) : 0;
	return rbc_now + rbc_boost;
}

void
Task::set_priority(int value)
{
	if (priority == value) {
		// don't mess with task order
		return;
	}
	session().update_task_priority(this, value);
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

void
Task::futex_wait(void* futex, uint32_t val)
{
	static_assert(sizeof(val) == sizeof(long),
		      "Sorry, need to implement Task::read_int().");
	// Wait for *sync_addr == sync_val.  This implementation isn't
	// pretty, but it's pretty much the best we can do with
	// available kernel tools.
	//
	// TODO: find clever way to avoid busy-waiting.
	while (val != uint32_t(read_word(futex))) {
		// Try to give our scheduling slot to the kernel
		// thread that's going to write sync_addr.
		sched_yield();
	}
}

unsigned long
Task::get_ptrace_eventmsg()
{
	unsigned long msg;
	xptrace(PTRACE_GETEVENTMSG, nullptr, &msg);
	return msg;
}

void
Task::get_siginfo(siginfo_t* si)
{
	xptrace(PTRACE_GETSIGINFO, nullptr, si);
}

TraceIfstream&
Task::ifstream()
{
	return session_replay->ifstream();
}

TraceOfstream&
Task::ofstream()
{
	return session_record->ofstream();
}

void*
Task::init_buffers(void* map_hint, int share_desched_fd)
{
	// NB: the tracee can't be interrupted with a signal while
	// we're processing the rrcall, because it's masked off all
	// signals.
	struct current_state_buffer state;
	prepare_remote_syscalls(this, &state);

	// Arguments to the rrcall.
	void* child_args = (void*)state.regs.arg1();
	struct rrcall_init_buffers_params args;
	read_mem(child_args, &args);

	ASSERT(this,
	       rr_flags()->use_syscall_buffer == !!args.syscallbuf_enabled)
		<<"Tracee things syscallbuf is "
		<< (args.syscallbuf_enabled ? "en" : "dis")
		<<"abled, but tracer thinks "
		<< (rr_flags()->use_syscall_buffer ? "en" : "dis") <<"abled";

	void* child_map_addr = nullptr;
	if (args.syscallbuf_enabled) {
		traced_syscall_ip = args.traced_syscall_ip;
		untraced_syscall_ip = args.untraced_syscall_ip;
		args.syscallbuf_ptr = child_map_addr =
				      init_syscall_buffer(&state, map_hint);
		init_desched_fd(&state, &args, share_desched_fd);
		// Zero out the child buffers we may have used here.
		// They may contain "real" fds, which in general will
		// not be the same across record/replay.
		write_socketcall_args(this, args.args_vec, 0, 0, 0);
		write_mem(args.fdptr, 0);
	} else {
		args.syscallbuf_ptr = nullptr;
	}
	
	// Return the mapped buffers to the child.
	write_mem(child_args, args);

	// The tracee doesn't need this addr returned, because it's
	// already written to the inout |args| param, but we stash it
	// away in the return value slot so that we can easily check
	// that we map the segment at the same addr during replay.
	state.regs.set_syscall_result((uintptr_t)child_map_addr);
	syscallbuf_hdr->locked = is_desched_sig_blocked();
	finish_remote_syscalls(this, &state);

	return child_map_addr;
}

void
Task::destroy_buffers(int which)
{
	struct current_state_buffer state;
	prepare_remote_syscalls(this, &state);

	if (DESTROY_SCRATCH & which) {
		remote_syscall2(this, &state, SYS_munmap,
				scratch_ptr, scratch_size);
		vm()->unmap(scratch_ptr, scratch_size);
	}
	if ((DESTROY_SYSCALLBUF & which) && syscallbuf_child) {
		remote_syscall2(this, &state, SYS_munmap,
				syscallbuf_child, num_syscallbuf_bytes);
		vm()->unmap(syscallbuf_child, num_syscallbuf_bytes);
		remote_syscall1(this, &state, SYS_close, desched_fd_child);
	}
	finish_remote_syscalls(this, &state);
}

bool
Task::is_arm_desched_event_syscall()
{
	return (is_desched_event_syscall()
		&& PERF_EVENT_IOC_ENABLE == regs().arg2());
}

bool
Task::is_desched_event_syscall()
{
	return (SYS_ioctl == regs().original_syscallno()
		&& (desched_fd_child == (int)regs().arg1_signed()
		    || desched_fd_child == REPLAY_DESCHED_EVENT_FD));
}

bool
Task::is_disarm_desched_event_syscall()
{
	return (is_desched_event_syscall()
		&& PERF_EVENT_IOC_DISABLE == regs().arg2());
}

bool
Task::is_probably_replaying_syscall()
{
	assert(session_replay);
	// If the tracee is at our syscall entry points, we know for
	// sure it's entering/exiting/just-exited a syscall.
	return (is_traced_syscall() || is_untraced_syscall()
		// Otherwise, we assume that if original_syscallno() has been
		// saved from syscallno(), then the tracee is in a syscall.
		// This seems to be the heuristic used by the linux
		// kernel for /proc/PID/syscall.
		|| regs().original_syscallno() >= 0);
}

bool
Task::is_ptrace_seccomp_event() const
{
	int event = ptrace_event();
	return (PTRACE_EVENT_SECCOMP_OBSOLETE == event ||
		PTRACE_EVENT_SECCOMP == event);
}

bool
Task::is_sig_blocked(int sig) const
{
	int sig_bit = sig - 1;
	return (blocked_sigs >> sig_bit) & 1;
}

bool
Task::is_sig_ignored(int sig) const
{
	return sighandlers->get(sig).ignored(sig);
}

bool
Task::is_syscall_restart()
{
	int syscallno = regs().original_syscallno();
	bool must_restart = (SYS_restart_syscall == syscallno);
	bool is_restart = false;
	const Registers* old_regs;

	LOG(debug) <<"  is syscall interruption of recorded " << ev()
		   <<"? (now "<< syscallname(syscallno) <<")";

	if (EV_SYSCALL_INTERRUPTION != ev().type()) {
		goto done;
	}

	old_regs = &ev().Syscall().regs;
	/* It's possible for the tracee to resume after a sighandler
	 * with a fresh syscall that happens to be the same as the one
	 * that was interrupted.  So we check here if the args are the
	 * same.
	 *
	 * Of course, it's possible (but less likely) for the tracee
	 * to incidentally resume with a fresh syscall that just
	 * happens to have the same *arguments* too.  But in that
	 * case, we would usually set up scratch buffers etc the same
	 * was as for the original interrupted syscall, so we just
	 * save a step here.
	 *
	 * TODO: it's possible for arg structures to be mutated
	 * between the original call and restarted call in such a way
	 * that it might change the scratch allocation decisions. */
	if (SYS_restart_syscall == syscallno) {
		must_restart = true;
		syscallno = ev().Syscall().no;
		LOG(debug) <<"  (SYS_restart_syscall)";
	}
	if (ev().Syscall().no != syscallno) {
		LOG(debug) <<"  interrupted %s"<< ev() <<" != "
			   << syscallname(syscallno);
		goto done;
	}
	if (!(old_regs->arg1() == regs().arg1()
	      && old_regs->arg2() == regs().arg2()
	      && old_regs->arg3() == regs().arg3()
	      && old_regs->arg4() == regs().arg4()
	      && old_regs->arg5() == regs().arg5()
	      && old_regs->arg6() == regs().arg6())) {
		LOG(debug) <<"  regs different at interrupted "
			   << syscallname(syscallno);
		goto done;
	}
	is_restart = true;

done:
	ASSERT(this, !must_restart || is_restart)
		<<"Must restart %s"<< syscallname(syscallno) <<" but won't";
	if (is_restart) {
		LOG(debug) <<"  restart of " << syscallname(syscallno);
	}
	return is_restart;
}

void
Task::log_pending_events() const
{
	ssize_t depth = pending_events.size();

	assert(depth > 0);
	if (1 == depth) {
		LOG(info) <<"(no pending events)";
		return;
	}

	/* The event at depth 0 is the placeholder event, which isn't
	 * useful to log.  Skip it. */
	for (auto it = pending_events.rbegin(); it != pending_events.rend();
	     ++it) {
		it->log();
	}
}

bool
Task::may_be_blocked() const
{
	return (EV_SYSCALL == ev().type()
		&& PROCESSING_SYSCALL == ev().Syscall().state)
		|| (EV_SIGNAL_DELIVERY == ev().type()
		    && ev().Signal().delivered);
}

void
Task::maybe_save_rbc_slop(const Event& ev)
{
	if (!ev.has_rbc_slop()) {
		reset_hpc(this, 0);
		rbc_slop = 0;
		rbc_boost = 0;
	}
	rbc_slop = read_rbc(hpc);
}

void
Task::adjust_for_rbc_slop(int64_t* target)
{
	assert(*target >= rbc_slop);

	*target -= rbc_slop;
	reset_hpc(this, 0);
	rbc_slop = 0;
}

void
Task::maybe_update_vm(int syscallno, int state)
{
	// We have to use the recorded_regs during replay because they
	// have the return value set in syscall_result().  We may not have
	// advanced regs() to that point yet.
	const Registers& r = RECORD == rr_flags()->option ?
					   regs() : trace.recorded_regs;

	if (STATE_SYSCALL_EXIT != state
	    || (SYSCALL_FAILED(r.syscall_result_signed()) &&
	        SYS_mprotect != syscallno)) {
		return;
	}
	switch (syscallno) {
	case SYS_brk: {
		void* addr = reinterpret_cast<void*>(r.arg1());
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
		LOG(debug) <<"(mmap2 will receive / has received direct processing)";
		return;
	}
	case SYS_mprotect: {
		void* addr = reinterpret_cast<void*>(r.arg1());
		size_t num_bytes = r.arg2();
		int prot = r.arg3_signed();
		return vm()->protect(addr, num_bytes, prot);
	}
	case SYS_mremap: {
		if (SYSCALL_FAILED(r.syscall_result_signed()) &&
		    -ENOMEM != r.syscall_result_signed()) {
			return;
		}
		void* old_addr = reinterpret_cast<void*>(r.arg1());
		size_t old_num_bytes = r.arg2();
		void* new_addr = reinterpret_cast<void*>(r.syscall_result());
		size_t new_num_bytes = r.arg3();
		return vm()->remap(old_addr, old_num_bytes,
				   new_addr, new_num_bytes);
	}
	case SYS_munmap: {
		void* addr = reinterpret_cast<void*>(r.arg1());
		size_t num_bytes = r.arg2();
		return vm()->unmap(addr, num_bytes);
	}
	}
}

void
Task::move_ip_before_breakpoint()
{
	// TODO: assert that this is at a breakpoint trap.
	Registers r = regs();
	r.set_ip(r.ip() - sizeof(AddressSpace::breakpoint_insn));
	set_regs(r);
}

static string prname_from_exe_image(const string& e)
{
	size_t last_slash = e.rfind('/');
	string basename =
		(last_slash != e.npos) ? e.substr(last_slash + 1) : e;
	return basename.substr(0, 15);
}

void
Task::pre_exec()
{
	execve_file = read_c_str((void*)regs().arg1());
	if (execve_file[0] != '/') {
		char buf[PATH_MAX];
		snprintf(buf, sizeof(buf),
			 "/proc/%d/cwd/%s", real_tgid(),
			 execve_file.c_str());
		execve_file = buf;
	}
	char abspath[PATH_MAX];
	if (realpath(execve_file.c_str(), abspath)) {
		execve_file = abspath;
	}
}

void
Task::post_exec()
{
	sighandlers = sighandlers->clone();
	sighandlers->reset_user_handlers();
	as->erase_task(this);
	assert(execve_file.size() > 0);
	auto a = session().create_vm(this, execve_file);
	as.swap(a);
	// XXX should we re-create our TaskGroup here too?
	prname = prname_from_exe_image(as->exe_image());
}

void
Task::record_current_event()
{
	record_event(ev());
}

void
Task::record_event(const Event& ev)
{
	maybe_flush_syscallbuf();

	struct trace_frame frame;
	frame.global_time = ofstream().time();
	frame.thread_time = thread_time++;
	frame.tid = tid;
	frame.ev = ev.encode();
	if (ev.has_exec_info()) {
		frame.rbc = read_rbc(hpc);
#ifdef HPC_ENABLE_EXTRA_PERF_COUNTERS
		frame.hw_interrupts = read_hw_int(hpc);
		frame.page_faults = read_page_faults(hpc);
		frame.insts = read_insts(hpc);
#endif
		frame.recorded_regs = regs();
	}

	if (should_dump_memory(this, frame)) {
		dump_process_memory(this, frame.global_time, "rec");
	}
	if (should_checksum(this, frame)) {
		checksum_process_memory(this, frame.global_time);
	}

	ofstream() << frame;
	if (frame.ev.has_exec_info) {
		reset_hpc(this, rr_flags()->max_rbc);
	}
}

void
Task::record_local(void* addr, ssize_t num_bytes, const void* data)
{
	maybe_flush_syscallbuf();

	struct raw_data buf;
	buf.addr = addr;
	buf.data.assign((const byte*)data, (const byte*)data + num_bytes);
	buf.ev = ev().encode();
	buf.global_time = ofstream().time();
	ofstream() << buf;
}

void
Task::record_remote(void* addr, ssize_t num_bytes)
{
	// We shouldn't be recording a scratch address.
	ASSERT(this, !addr || addr != scratch_ptr);

	maybe_flush_syscallbuf();

	struct raw_data buf;
	buf.addr = addr;
	buf.ev = ev().encode();
	buf.global_time = ofstream().time();
 	if (addr && num_bytes > 0) {
		buf.data.resize(num_bytes);
		read_bytes_helper(addr, buf.data.size(), buf.data.data());
	}
	ofstream() << buf;
}

void
Task::record_remote_str(void* str)
{
	maybe_flush_syscallbuf();

	string s = read_c_str(str);
	struct raw_data buf;
	buf.addr = str;
	// Record the \0 byte.
	buf.data.assign(s.c_str(), s.c_str() + s.size() + 1);
	buf.ev = ev().encode();
	buf.global_time = ofstream().time();
	ofstream() << buf;
}

string
Task::read_c_str(void* child_addr)
{
	// XXX handle invalid C strings
	string str;
	while (true) {
		// We're only guaranteed that [child_addr,
		// end_of_page) is mapped.
		void* end_of_page = ceil_page_size((byte*)child_addr + 1);
		ssize_t nbytes = (byte*)end_of_page - (byte*)child_addr;
		char buf[nbytes];

		read_bytes_helper(child_addr, nbytes,
				  reinterpret_cast<byte*>(buf));
		for (int i = 0; i < nbytes; ++i) {
			if ('\0' == buf[i]) {
				return str;
			}
			str += buf[i];
		}
		child_addr = end_of_page;
	}
}

long
Task::read_word(void* child_addr)
{
	long word;
	read_mem(child_addr, &word);
	return word;
}

const Registers&
Task::regs()
{
	if (!registers_known) {
		LOG(debug) <<"  (refreshing register cache)";
		xptrace(PTRACE_GETREGS, nullptr, &registers);
		registers_known = true;
	}
	return registers;
}

static ssize_t dr_user_word_offset(size_t i)
{
	assert(i < NUM_X86_DEBUG_REGS);
	return offsetof(struct user, u_debugreg[0]) + sizeof(void*) * i;
}

uintptr_t
Task::debug_status()
{
	return fallible_ptrace(PTRACE_PEEKUSER, (void*)dr_user_word_offset(6),
			       nullptr);
}

void*
Task::watchpoint_addr(size_t i)
{
	assert(i < NUM_X86_WATCHPOINTS);
	return (void*)fallible_ptrace(PTRACE_PEEKUSER,
				      (void*)dr_user_word_offset(i),
				      nullptr);
}

void
Task::remote_memcpy(void* dst, const void* src, size_t num_bytes)
{
	// XXX this could be more efficient
	byte buf[num_bytes];
	read_bytes_helper((void*)src, num_bytes, buf);
	write_bytes_helper(dst, num_bytes, buf);
}

bool
Task::resume_execution(ResumeRequest how, WaitRequest wait_how, int sig)
{
	LOG(debug) <<"resuming execution with "<< ptrace_req_name(how);
	xptrace(how, nullptr, (void*)(uintptr_t)sig);
	registers_known = false;
	if (RESUME_NONBLOCKING == wait_how) {
		return true;
	}
	return wait();
}

Session&
Task::session()
{
	if (session_record) {
		return *session_record;
	}
	return *session_replay;
}

RecordSession&
Task::record_session()
{
	return *session_record;
}

ReplaySession&
Task::replay_session()
{
	return *session_replay;
}

ssize_t
Task::set_data_from_trace()
{
	struct raw_data buf;
	ifstream() >> buf;
	if (buf.addr && buf.data.size() > 0) {
		write_bytes_helper(buf.addr, buf.data.size(), buf.data.data());
	}
	return buf.data.size();
}

void
Task::set_return_value_from_trace()
{
	Registers r = regs();
	r.set_syscall_result(trace.recorded_regs.syscall_result());
	set_regs(r);
}

void
Task::set_regs(const Registers& regs)
{
	registers = regs;
	xptrace(PTRACE_SETREGS, nullptr, (void*)&registers);
	registers_known = true;
}

enum WatchBytesX86 {
    BYTES_1 = 0x00, BYTES_2 = 0x01, BYTES_4 = 0x03, BYTES_8 = 0x02
};
static WatchBytesX86 num_bytes_to_dr_len(size_t num_bytes)
{
	switch (num_bytes) {
	case 1:
		return BYTES_1;
	case 2:
		return BYTES_2;
	case 4:
		return BYTES_4;
	case 8:
		return BYTES_8;
	default:
		FATAL() <<"Unsupported breakpoint size "<< num_bytes;
		return WatchBytesX86(-1); // not reached
	}
}

bool
Task::set_debug_regs(const DebugRegs& regs)
{
	struct DebugControl {
		uintptr_t packed() { return *(uintptr_t*)this; }

		uintptr_t dr0_local : 1;
		uintptr_t dr0_global : 1;
		uintptr_t dr1_local : 1;
		uintptr_t dr1_global : 1;
		uintptr_t dr2_local : 1;
		uintptr_t dr2_global : 1;
		uintptr_t dr3_local : 1;
		uintptr_t dr3_global : 1;

		uintptr_t ignored : 8;

		WatchType dr0_type : 2;
		WatchBytesX86 dr0_len : 2;
		WatchType dr1_type : 2;
		WatchBytesX86 dr1_len : 2;
		WatchType dr2_type : 2;
		WatchBytesX86 dr2_len : 2;
		WatchType dr3_type : 2;
		WatchBytesX86 dr3_len : 2;
	} dr7 = { 0 };
	static_assert(sizeof(DebugControl) == sizeof(uintptr_t),
		      "Can't pack DebugControl");

	// Reset the debug status since we're about to change the set
	// of programmed watchpoints.
	xptrace(PTRACE_POKEUSER, (void*)dr_user_word_offset(6), 0);
	// Ensure that we clear the programmed watchpoints in case
	// enabling one of them fails.  We guarantee atomicity to the
	// caller.
	xptrace(PTRACE_POKEUSER, (void*)dr_user_word_offset(7), 0);
	if (regs.size() > NUM_X86_WATCHPOINTS) {
		return false;
	}

	size_t dr = 0;
	for (auto reg : regs) {
		if (fallible_ptrace(PTRACE_POKEUSER,
				    (void*)dr_user_word_offset(dr),
				    reg.addr)) {
			return false;
		}
		switch (dr++) {
#define CASE_ENABLE_DR(_dr7, _i, _reg)					\
			case _i:					\
				_dr7.dr## _i ##_local = 1;		\
				_dr7.dr## _i ##_type = _reg.type;	\
				_dr7.dr## _i ##_len = num_bytes_to_dr_len(_reg.num_bytes); \
				break
		CASE_ENABLE_DR(dr7, 0, reg);
		CASE_ENABLE_DR(dr7, 1, reg);
		CASE_ENABLE_DR(dr7, 2, reg);
		CASE_ENABLE_DR(dr7, 3, reg);
#undef CASE_ENABLE_DR
		default:
			FATAL() <<"There's no debug register "<< dr;
		}
	}
	return 0 == fallible_ptrace(PTRACE_POKEUSER,
				    (void*)dr_user_word_offset(7),
				    (void*)dr7.packed());
}

void
Task::set_thread_area(void* tls)
{
	read_mem(tls, &thread_area);
	thread_area_valid = true;
}

const struct user_desc*
Task::tls() const
{
	return thread_area_valid ? &thread_area : nullptr;
}

void
Task::set_tid_addr(void* tid_addr)
{
	LOG(debug) <<"updating cleartid futex to "<< tid_addr;
	tid_futex = tid_addr;
}

void
Task::signal_delivered(int sig)
{
	Sighandler& h = sighandlers->get(sig);
	if (h.resethand) {
		h = Sighandler();
	}
}

sig_handler_t
Task::signal_disposition(int sig) const
{
	return sighandlers->get(sig).sa.k_sa_handler;
}

bool
Task::signal_has_user_handler(int sig) const
{
	return sighandlers->get(sig).is_user_handler();
}

const kernel_sigaction&
Task::signal_action(int sig) const
{
	return sighandlers->get(sig).sa;
}

void
Task::stash_sig()
{
	assert(pending_sig());
	ASSERT(this, !has_stashed_sig())
		<< "Tried to stash "<< signalname(pending_sig()) <<" when "
		<< signalname(stashed_si.si_signo) <<" was already stashed.";
	stashed_wait_status = wait_status;
	get_siginfo(&stashed_si);
}

const siginfo_t&
Task::pop_stash_sig()
{
	assert(has_stashed_sig());
	force_status(stashed_wait_status);
	stashed_wait_status = 0;
	return stashed_si;
}

const string&
Task::trace_dir() const
{
	return trace_fstream().dir();
}

uint32_t
Task::trace_time() const
{
	return trace_fstream().time();
}

void
Task::update_prname(void* child_addr)
{
	struct { char chars[16]; } name;
	read_mem(child_addr, &name);
	name.chars[sizeof(name.chars) - 1] = '\0';
	prname = name.chars;
}

void
Task::update_sigaction()
{
	int sig = regs().arg1_signed();
	void* new_sigaction = (void*)regs().arg2();
	if (0 == regs().syscall_result() && new_sigaction) {
		// A new sighandler was installed.  Update our
		// sighandler table.
		// TODO: discard attempts to handle or ignore signals
		// that can't be by POSIX
		struct kernel_sigaction sa;
		read_mem(new_sigaction, &sa);
		sighandlers->get(sig) = Sighandler(sa);
	}
}

void
Task::update_sigmask()
{
	int how = regs().arg1_signed();
	void* setp = (void*)regs().arg2();

	if (SYSCALL_FAILED(regs().syscall_result_signed()) || !setp) {
		return;
	}

	ASSERT(this, (!syscallbuf_hdr || !syscallbuf_hdr->locked
		      || is_desched_sig_blocked()))
	       <<"syscallbuf is locked but SIGSYS isn't blocked";

	sig_set_t set;
	read_mem(setp, &set);

	// Update the blocked signals per |how|.
	switch (how) {
	case SIG_BLOCK:
		blocked_sigs |= set;
		break;
	case SIG_UNBLOCK:
		blocked_sigs &= ~set;
		break;
	case SIG_SETMASK:
		blocked_sigs = set;
		break;
	default:
		FATAL() <<"Unknown sigmask manipulator "<< how;
	}

	// In the syscallbuf, we rely on SIGSYS being raised when
	// tracees are descheduled in blocked syscalls.  But
	// unfortunately, if tracees block SIGSYS, then we don't get
	// notification of the pending signal and deadlock.  If we did
	// get those notifications, this code would be unnecessary.
	//
	// So we lock the syscallbuf while the desched signal is
	// blocked, which prevents the tracee from attempting a
	// buffered call.
	if (syscallbuf_hdr) {
		syscallbuf_hdr->locked = is_desched_sig_blocked();
	}
}

// The Task currently being wait()d on, or nullptr.
// |waiter_was_interrupted| if a PTRACE_INTERRUPT had to be applied to
// |waiter| to get it to stop.
static Task* waiter;
static bool waiter_was_interrupted;

bool
Task::wait()
{
	LOG(debug) <<"going into blocking waitpid("<< tid <<") ...";

	// We only need this during recording.  If tracees go runaway
	// during replay, something else is at fault.
	bool enable_wait_interrupt = (RECORD == rr_flags()->option);
	if (enable_wait_interrupt) {
		waiter = this;
		// Where does the 3 seconds come from?  No especially
		// good reason.  We want this to be pretty high,
		// because it's a last-ditch recovery mechanism, not a
		// primary thread scheduler.  Though in theory the
		// PTRACE_INTERRUPT's shouldn't interfere with other
		// events, that's hard to test thoroughly so try to
		// avoid it.
		alarm(3);

		// Set the wait_status to a sentinel value so that we
		// can hopefully recognize race conditions in the
		// SIGALRM handler.
		wait_status = -1;
	}
	pid_t ret = waitpid(tid, &wait_status, __WALL);
	if (enable_wait_interrupt) {
		waiter = nullptr;
		alarm(0);
	}

	if (0 > ret && EINTR == errno) {
		LOG(debug) <<"  waitpid("<< tid <<") interrupted!";
		return false;
	}
	LOG(debug) <<"  waitpid("<< tid <<") returns "<< ret <<"; status "
		   << HEX(wait_status);
	ASSERT(this, tid == ret)
		<<"waitpid("<< tid <<") failed with "<< ret;;
	// If some other ptrace-stop happened to race with our
	// PTRACE_INTERRUPT, then let the other event win.  We only
	// want to interrupt tracees stuck running in userspace.
	if (waiter_was_interrupted && PTRACE_EVENT_STOP == ptrace_event()
	    && (SIGTRAP == WSTOPSIG(wait_status)
		// We sometimes see SIGSTOP at interrupts, though the
		// docs don't mention that.
		|| SIGSTOP == WSTOPSIG(wait_status))) {
		LOG(warn) <<"Forced to PTRACE_INTERRUPT tracee";
		stashed_wait_status = wait_status =
				      (HPC_TIME_SLICE_SIGNAL << 8) | 0x7f;
		memset(&stashed_si, 0, sizeof(stashed_si));
		stashed_si.si_signo = HPC_TIME_SLICE_SIGNAL;
		stashed_si.si_fd = hpc->rbc.fd;
		stashed_si.si_code = POLL_IN;
		// Starve the runaway task of CPU time.  It just got
		// the equivalent of hundreds of time slices.
		succ_event_counter = numeric_limits<int>::max() / 2;
	} else if (waiter_was_interrupted) {
		LOG(debug) <<"  PTRACE_INTERRUPT raced with another event "
			   << HEX(wait_status);
	}
	waiter_was_interrupted = false;
	return true;
}

bool
Task::try_wait()
{
	pid_t ret = waitpid(tid, &wait_status, WNOHANG | __WALL | WSTOPPED);
	LOG(debug) <<"waitpid("<< tid <<", NOHANG) returns "<< ret
		   <<", status "<< HEX(wait_status);
	ASSERT(this, 0 <= ret)
		<<"waitpid("<< tid <<", NOHANG) failed with "<< ret;
	return ret == tid;
}

/**
 * Prepare this process and its ancestors for recording/replay by
 * preventing direct access to sources of nondeterminism, and ensuring
 * that rr bugs don't adversely affect the underlying system.
 */
static void set_up_process(void)
{
	int orig_pers;

	/* TODO tracees can probably undo some of the setup below
	 * ... */

	/* Disable address space layout randomization, for obvious
	 * reasons, and ensure that the layout is otherwise well-known
	 * ("COMPAT").  For not-understood reasons, "COMPAT" layouts
	 * have been observed in certain recording situations but not
	 * in replay, which causes divergence. */
	if (0 > (orig_pers = personality(0xffffffff))) {
		FATAL() <<"error getting personaity";
	}
	if (0 > personality(orig_pers | ADDR_NO_RANDOMIZE |
			    ADDR_COMPAT_LAYOUT)) {
		FATAL() <<"error disabling randomization";
	}
	/* Trap to the rr process if a 'rdtsc' instruction is issued.
	 * That allows rr to record the tsc and replay it
	 * deterministically. */
	if (0 > prctl(PR_SET_TSC, PR_TSC_SIGSEGV, 0, 0, 0)) {
		FATAL() <<"error setting up prctl";
	}
	// If the rr process dies, prevent runaway tracee processes
	// from dragging down the underlying system.
	//
	// TODO: this isn't inherited across fork().
	if (0 > prctl(PR_SET_PDEATHSIG, SIGKILL)) {
		FATAL() <<"Couldn't set parent-death signal";
	}
}

/*static*/int
Task::pending_sig_from_status(int status)
{
	if (status == 0) {
		return 0;
	}
	int sig = stop_sig_from_status(status);
	switch (sig) {
	case (SIGTRAP | 0x80):
		/* We ask for PTRACE_O_TRACESYSGOOD, so this was a
		 * trap for a syscall.  Pretend like it wasn't a
		 * signal. */
		return 0;
	case SIGTRAP:
		/* For a "normal" SIGTRAP, it's a ptrace trap if
		 * there's a ptrace event.  If so, pretend like we
		 * didn't get a signal.  Otherwise it was a genuine
		 * TRAP signal raised by something else (most likely a
		 * debugger breakpoint). */
		return ptrace_event_from_status(status) ? 0 : SIGTRAP;
	default:
		/* XXX do we really get the high bit set on some
		 * SEGVs? */
		return sig & ~0x80;
	}
}

Task*
Task::clone(int flags, void* stack, void* tls, void* cleartid_addr,
	    pid_t new_tid, pid_t new_rec_tid,
	    Session* other_session)
{
	auto& sess = other_session ? *other_session : session();
	Task* t = new Task(new_tid, new_rec_tid, priority);

	t->session_record = session_record;
	t->session_replay = session_replay;
	t->syscallbuf_lib_start = syscallbuf_lib_start;
	t->syscallbuf_lib_end = syscallbuf_lib_end;
	t->blocked_sigs = blocked_sigs;
	if (CLONE_SHARE_SIGHANDLERS & flags) {
		t->sighandlers = sighandlers;
	} else {
		auto sh = Sighandlers::create();
		t->sighandlers.swap(sh);
	}
	if (CLONE_SHARE_TASK_GROUP & flags) {
		t->tg = tg;
		tg->insert_task(t);
	} else {
		auto g = sess.create_tg(t);
		t->tg.swap(g);
	}
	if (CLONE_SHARE_VM & flags) {
		t->as = as;
	} else {
		t->as = sess.clone(as);
	}
	if (stack) {
		const Mapping& m = 
			t->as->mapping_of((byte*)stack - page_size(),
					  page_size()).first;
		LOG(debug) <<"mapping stack for "<< new_tid <<" at "<< m;
		t->as->map(m.start, m.num_bytes(), m.prot, m.flags,
			   m.offset, MappableResource::stack(new_tid));
		t->top_of_stack = stack;
	}
	// Clone children, both thread and fork, inherit the parent
	// prname.
	t->prname = prname;
	if (CLONE_CLEARTID & flags) {
		LOG(debug) <<"cleartid futex is "<< cleartid_addr;
		assert(cleartid_addr);
		t->tid_futex = cleartid_addr;
	} else {
		LOG(debug) <<"(clone child not enabling CLEARTID)";
	}
	if (CLONE_SET_TLS & flags) {
		t->set_thread_area(tls);
	}

	t->as->insert_task(t);
	return t;
}

Task*
Task::os_fork_into(Session* session)
{
	struct current_state_buffer state;
	prepare_remote_syscalls(this, &state);
	Task* child = os_clone(this, session, &state, rec_tid,
			       // Most likely, we'll be setting up a
			       // CLEARTID futex.  That's not done
			       // here, but rather later in
			       // |copy_state()|.
			       //
			       // We also don't use any of the SETTID
			       // flags because that earlier work will
			       // be copied by fork()ing the address
			       // space.
			       SIGCHLD);
	finish_remote_syscalls(this, &state);
	// When we forked ourselves, the child inherited the setup we
	// did to make the clone() call.  So we have to "finish" the
	// remote calls (i.e. undo fudged state) in the child too,
	// even though we never made any there.
	state.pid = child->tid;
	finish_remote_syscalls(child, &state);
	return child;
}

Task*
Task::os_clone_into(Task* task_leader, struct current_state_buffer* state)
{
	return os_clone(task_leader, &task_leader->session(), state,
			rec_tid,
			// We don't actually /need/ to specify the
			// SIGHAND/SYSVMEM flags because those things
			// are emulated in the tracee.  But we use the
			// same flags as glibc to be on the safe side
			// wrt kernel bugs.
			//
			// We don't pass CLONE_SETTLS here *only*
			// because we'll do it later in
			// |copy_state()|.
			//
			// See |os_fork_into()| above for discussion
			// of the CTID flags.
			(CLONE_VM | CLONE_FS | CLONE_FILES |
			 CLONE_SIGHAND | CLONE_THREAD |
			 CLONE_SYSVSEM),
			stack());
}

void
Task::copy_state(Task* from)
{
	long err;
	set_regs(from->regs());
	struct current_state_buffer state;
	prepare_remote_syscalls(this, &state);
	{
		struct restore_mem restore_prname;
		char prname[16];
		strncpy(prname, from->name().c_str(), sizeof(prname));
		void* remote_prname = push_tmp_mem(this, &state,
						   (const byte*)prname,
						   sizeof(prname),
						   &restore_prname);
		LOG(debug) <<"    setting name to "<< prname;
		err = remote_syscall2(this, &state, SYS_prctl,
				      PR_SET_NAME, remote_prname);
		ASSERT(this, 0 == err);
		update_prname(remote_prname);
		pop_tmp_mem(this, &state, &restore_prname);
	}

	if (from->robust_list()) {
		set_robust_list(from->robust_list(), from->robust_list_len());
		LOG(debug) <<"    setting robust-list "<< this->robust_list()
			   <<" (size "<< this->robust_list_len() <<")";
		err = remote_syscall2(this, &state, SYS_set_robust_list,
				      this->robust_list(),
				      this->robust_list_len());
		ASSERT(this, 0 == err);
	}

	if (const struct user_desc* tls = from->tls()) {
		struct restore_mem restore_tls;
		void* remote_tls = push_tmp_mem(this, &state,
						(const byte*)tls, sizeof(*tls),
						&restore_tls);
		LOG(debug) <<"    setting tls "<< remote_tls;
		err = remote_syscall1(this, &state, SYS_set_thread_area,
				      remote_tls);
		ASSERT(this, 0 == err);
		set_thread_area(remote_tls);
		pop_tmp_mem(this, &state, &restore_tls);
	}

	if (void* ctid = from->tid_addr()) {
		err = remote_syscall1(this, &state, SYS_set_tid_address, ctid);
		ASSERT(this, tid == err);
	}

	if (from->syscallbuf_child) {
		// All these fields are preserved by the fork.
		traced_syscall_ip = from->traced_syscall_ip;
		untraced_syscall_ip = from->untraced_syscall_ip;
		syscallbuf_child = from->syscallbuf_child;
		num_syscallbuf_bytes = from->num_syscallbuf_bytes;
		desched_fd_child = from->desched_fd_child;

		// The syscallbuf is mapped as a shared segment
		// between rr and the tracee.  So we have to unmap it,
		// create a copy, and then re-map the copy in rr and
		// the tracee.
		void* map_hint = from->syscallbuf_child;
		destroy_buffers(DESTROY_SYSCALLBUF);
		destroy_local_buffers();

		syscallbuf_child = init_syscall_buffer(&state, map_hint);
		ASSERT(this, from->syscallbuf_child == syscallbuf_child);
		// Ensure the copied syscallbuf has the same contents
		// as the old one, for consistency checking.
		memcpy(syscallbuf_hdr, from->syscallbuf_hdr,
		       num_syscallbuf_bytes);
	}

	finish_remote_syscalls(this, &state);

	// The scratch buffer (for now) is merely a private mapping in
	// the remote task.  The CoW copy made by fork()'ing the
	// address space has the semantics we want.  It's not used in
	// replay anyway.
	scratch_ptr = from->scratch_ptr;
	scratch_size = from->scratch_size;

	// Whatever |from|'s last wait status was is what ours would
	// have been.
	wait_status = from->wait_status;

	// These are only metadata that have been inferred from the
	// series of syscalls made by the trace so far.
	blocked_sigs = from->blocked_sigs;
	pending_events = from->pending_events;
	trace = from->trace;
	rbc_slop = from->rbc_slop;

	// We, the deepfork clone of |from|, need to have the same
	// |effective_rbc()| value as |from|.  The |rbc_boost| helper
	// accounts for rcb's that |from| has seen that we haven't.
	rbc_boost = from->effective_rbc();

	// In all probability, |from| has started counting rcbs by
	// now.  Kick on the counter so that we can match its rbc
	// targets at significant events.
	//
	// TODO: rbc should always be initialized to a known value.
	reset_hpc(this, 0);
}

void
Task::destroy_local_buffers()
{
	close(desched_fd);
	munmap(syscallbuf_hdr, num_syscallbuf_bytes);
}

void
Task::detach_and_reap()
{
	if (tid_futex) {
		static_assert(sizeof(int32_t) == sizeof(long),
			      "Sorry, need to add Task::read_int()");
		// This read also ensures that child_mem_fd is valid
		// before the tracee exits.  Otherwise we might not be
		// open the fd below.  See TODO comment in Task ctor.
		int32_t tid_addr_val = read_word(tid_futex);
		ASSERT(this, rec_tid == tid_addr_val)
			<<"tid addr should be "<< rec_tid <<", but is "<< tid_addr_val;
	}

	// XXX: why do we detach before harvesting?
	fallible_ptrace(PTRACE_DETACH, nullptr, nullptr);
	if (unstable) {
		// In addition to problems described in the long
		// comment at the prototype of this function, unstable
		// exits may result in the kernel *not* clearing the
		// futex, for example for fatal signals.  So we would
		// deadlock waiting on the futex.
		LOG(warn) << tid <<" is unstable; not blocking on its termination";
		return;
	}

	LOG(debug) <<"Joining with exiting "<< tid <<" ...";
	while (true) {
		int err = waitpid(tid, &wait_status, __WALL);
		if (-1 == err && ECHILD == errno) {
			LOG(debug) <<" ... ECHILD";
			break;
		} else if (-1 == err) {
			assert(EINTR == errno);
		}
		if (err == tid && (exited() || signaled())) {
			LOG(debug) <<" ... exited with status "
				   << HEX(wait_status);
			break;
		} else if (err == tid) {
			assert(PTRACE_EVENT_EXIT == ptrace_event());
		}
	}

	if (tid_futex && as->task_set().size() > 0) {
		// clone()'d tasks can have a pid_t* |ctid| argument
		// that's written with the new task's pid.  That
		// pointer can also be used as a futex: when the task
		// dies, the original ctid value is cleared and a
		// FUTEX_WAKE is done on the address. So
		// pthread_join() is basically a standard futex wait
		// loop.
		LOG(debug) <<"  waiting for tid futex "<< tid_futex
			   <<" to be cleared ...";
		futex_wait(tid_futex, 0);
	} else if(tid_futex) {
		// There are no other live tasks in this address
		// space, which means the address space just died
		// along with our exit.  So we can't read the futex.
		LOG(debug) <<"  (can't futex_wait last task in vm)";
	}
}

long
Task::fallible_ptrace(int request, void* addr, void* data)
{
	return ptrace(__ptrace_request(request), tid, addr, data);
}

int
Task::open_mem_fd()
{
	char path[PATH_MAX];
	snprintf(path, sizeof(path) - 1, "/proc/%d/mem", tid);
	int fd = open(path, O_RDWR);
	ASSERT(this, fd >= 0) <<"Failed to open "<< path;
	return fd;
}

void
Task::reopen_mem_fd()
{
	close(child_mem_fd);
	child_mem_fd = open_mem_fd();
}

void*
Task::init_syscall_buffer(struct current_state_buffer* state, void* map_hint)
{
	// Create the segment we'll share with the tracee.
	char shmem_name[PATH_MAX];
	format_syscallbuf_shmem_path(tid, shmem_name);
	int shmem_fd = create_shmem_segment(shmem_name,
					    SYSCALLBUF_BUFFER_SIZE);
	// Map the shmem fd in the child.
	int child_shmem_fd;
	{
		struct restore_mem restore_path;
		char proc_path[PATH_MAX];
		snprintf(proc_path, sizeof(proc_path), "/proc/%d/fd/%d",
			 getpid(), shmem_fd);
		void* child_path = push_tmp_str(this, state, proc_path,
						&restore_path);
		child_shmem_fd = remote_syscall3(this, state, SYS_open,
						 child_path, O_RDWR, 0600);
		if (0 > child_shmem_fd) {
			errno = -child_shmem_fd;
			FATAL() <<"Failed to open("<< proc_path <<") in tracee";
		}
		pop_tmp_mem(this, state, &restore_path);
	}

	// Map the segment in ours and the tracee's address spaces.
	void* map_addr;
	num_syscallbuf_bytes = SYSCALLBUF_BUFFER_SIZE;
	int prot = PROT_READ | PROT_WRITE;
	int flags = MAP_SHARED;
	off64_t offset_pages = 0;
	if ((void*)-1 == (map_addr = mmap(nullptr, num_syscallbuf_bytes,
					  prot, flags,
					  shmem_fd, offset_pages))) {
		FATAL() <<"Failed to mmap shmem region";
	}
	void* child_map_addr = (byte*)remote_syscall6(this, state, SYS_mmap2,
						      map_hint,
						      num_syscallbuf_bytes,
						      prot, flags,
						      child_shmem_fd,
						      offset_pages);
	syscallbuf_child = child_map_addr;
	syscallbuf_hdr = (struct syscallbuf_hdr*)map_addr;
	// No entries to begin with.
	memset(syscallbuf_hdr, 0, sizeof(*syscallbuf_hdr));

	vm()->map(child_map_addr, num_syscallbuf_bytes,
		  prot, flags, page_size() * offset_pages,
		  MappableResource::syscallbuf(rec_tid, shmem_fd,
					       shmem_name));

	close(shmem_fd);
	remote_syscall1(this, state, SYS_close, child_shmem_fd);

	return child_map_addr;
}

/**
 * Block until receiving an fd the other side of |sock| sent us, then
 * return the fd (valid in this address space).  Optionally return the
 * remote fd number that was shared to us in |remote_fdno|.
 */
static int recv_fd(int sock, int* remote_fdno)
{
	struct msghdr msg;
	int fd, remote_fd;
	struct iovec data;
	struct cmsghdr* cmsg;
	char cmsgbuf[CMSG_SPACE(sizeof(int))];

	memset(&msg, 0, sizeof(msg));

	data.iov_base = &remote_fd;
	data.iov_len = sizeof(remote_fd);
	msg.msg_iov = &data;
	msg.msg_iovlen = 1;

	msg.msg_control = cmsgbuf;
	msg.msg_controllen = sizeof(cmsgbuf);

	if (0 >= recvmsg(sock, &msg, 0)) {
		FATAL() <<"Failed to receive fd";
	}

	cmsg = CMSG_FIRSTHDR(&msg);
	assert(cmsg->cmsg_level == SOL_SOCKET
	       && cmsg->cmsg_type == SCM_RIGHTS);

	fd = *(int*)CMSG_DATA(cmsg);
	if (remote_fdno) {
		*remote_fdno = remote_fd;
	}

	return fd;
}

void
Task::init_desched_fd(struct current_state_buffer* state,
		      struct rrcall_init_buffers_params* args,
		      int share_desched_fd)
{
	// NB: this implementation could be vastly simplfied if we
	// were able to share the tracee's desched fd through its
	// /proc/fd entry.  However, as of linux 3.13.9, this doesn't
	// work.  So instead we do the SCM_RIGHTS dance.
	if (!share_desched_fd) {
		desched_fd_child = REPLAY_DESCHED_EVENT_FD;
		return;
	}

	// NB: the sockaddr prepared by the child uses the recorded
	// tid, so always must here. */
	struct sockaddr_un addr;
	prepare_syscallbuf_socket_addr(&addr, rec_tid);

	// Bind the server socket, but don't start listening yet.
	int listen_sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (::bind(listen_sock, (struct sockaddr*)&addr, sizeof(addr))) {
		FATAL() <<"Failed to bind listen socket";
	}
	if (listen(listen_sock, 1)) {
		FATAL() <<"Failed to mark listening for listen socket";
	}

	// Initiate tracee connect(), but don't wait for it to
	// finish.
	write_socketcall_args(this, args->args_vec, AF_UNIX, SOCK_STREAM, 0);
	int child_sock = remote_syscall2(this, state, SYS_socketcall,
					 SYS_SOCKET, args->args_vec);
	if (0 > child_sock) {
		errno = -child_sock;
		FATAL() <<"Failed to create child socket";
	}
	write_socketcall_args(this, args->args_vec, child_sock,
			      (uintptr_t)args->sockaddr,
			      sizeof(*args->sockaddr));
	remote_syscall(this, state, DONT_WAIT, SYS_socketcall,
		       SYS_CONNECT, (uintptr_t)args->args_vec, 0, 0, 0, 0);
	// Now the child is waiting for us to accept it.

	// Accept the child's connection and finish its syscall.
	//
	// XXX could be really anal and check credentials of
	// connecting endpoint ...
	int sock = accept(listen_sock, NULL, NULL);
	int child_ret;
	if ((child_ret = wait_remote_syscall(this, state, SYS_socketcall))) {
		errno = -child_ret;
		FATAL() <<"Failed to connect() in tracee";
	}
	// Socket name not needed anymore.
	unlink(addr.sun_path);

	// Pull the puppet strings to have the child share its desched
	// counter with us.  Similarly to above, we DONT_WAIT on the
	// call to finish, since it's likely not defined whether the
	// sendmsg() may block on our recvmsg()ing what the tracee
	// sent us (in which case we would deadlock with the tracee).
	write_socketcall_args(this, args->args_vec, child_sock,
			      (uintptr_t)args->msg, 0);
	remote_syscall(this, state, DONT_WAIT, SYS_socketcall,
		       SYS_SENDMSG, (uintptr_t)args->args_vec,
		       0, 0, 0, 0);
	// Child may be waiting on our recvmsg().

	// Read the shared fd and finish the child's syscall.
	desched_fd = recv_fd(sock, &desched_fd_child);
	if (0 >= wait_remote_syscall(this, state, SYS_socketcall)) {
		errno = -child_ret;
		FATAL() <<"Failed to sendmsg() in tracee";
	}

	// Socket magic is now done.
	close(listen_sock);
	close(sock);
	remote_syscall1(this, state, SYS_close, child_sock);
}


bool
Task::is_desched_sig_blocked()
{
	return is_sig_blocked(SYSCALLBUF_DESCHED_SIGNAL);
}

/** Send |sig| to task |tid| within group |tgid|. */
static int sys_tgkill(pid_t tgid, pid_t tid, int sig)
{
	return syscall(SYS_tgkill, tgid, tid, SIGKILL);
}

void
Task::kill()
{
	LOG(debug) <<"sending SIGKILL to "<< tid <<" ...";
	sys_tgkill(real_tgid(), tid, SIGKILL);

	wait();
	LOG(debug) <<"  ... status "<< HEX(status());

	if (WIFSIGNALED(wait_status)) {
		assert(SIGKILL == WTERMSIG(wait_status));
		// The task is already dead and reaped, so skip any
		// waitpid()'ing during cleanup.
		unstable = 1;
	} else {
		// If the task participated in an unstable exit, it's
		// probably already dead by now.
		assert(unstable || PTRACE_EVENT_EXIT == ptrace_event());
	}
	// Don't attempt to synchonize on the cleartid futex.  We
	// won't be able to reliably read it, and it's pointless
	// anyway.
	tid_futex = nullptr;
}

void
Task::maybe_flush_syscallbuf()
{
	if (EV_SYSCALLBUF_FLUSH == ev().type()) {
		// Already flushing.
		return;
	}
	if (!syscallbuf_hdr
	    || 0 == syscallbuf_hdr->num_rec_bytes 
	    || delay_syscallbuf_flush) {
		// No syscallbuf or no records.  No flushing to do.
		return;
	}
	// Write the entire buffer in one shot without parsing it,
	// because replay will take care of that.
	push_event(Event(EV_SYSCALLBUF_FLUSH, NO_EXEC_INFO));
	record_local(syscallbuf_child,
		     // Record the header for consistency checking.
		     syscallbuf_hdr->num_rec_bytes + sizeof(*syscallbuf_hdr),
		     syscallbuf_hdr);
	record_current_event();
	pop_event(EV_SYSCALLBUF_FLUSH);

	// Reset header.
	assert(!syscallbuf_hdr->abort_commit);
	if (!delay_syscallbuf_reset) {
		syscallbuf_hdr->num_rec_bytes = 0;
	}
	flushed_syscallbuf = 1;
}

static off64_t to_offset(void* addr)
{
	off64_t offset = (uintptr_t)addr;
	assert(offset <= off64_t(numeric_limits<unsigned long>::max()));
	return offset;
}

ssize_t
Task::read_bytes_fallible(void* addr, ssize_t buf_size, byte* buf)
{
	ASSERT(this, buf_size >= 0) <<"Invalid buf_size "<< buf_size;
	if (0 == buf_size) {
		return 0;
	}
	errno = 0;
	ssize_t nread = pread64(child_mem_fd, buf, buf_size, to_offset(addr));
	// We open the child_mem_fd just after being notified of
	// exec(), when the Task is created.  Trying to read from that
	// fd seems to return 0 with errno 0.  Reopening the mem fd
	// allows the pwrite to succeed.  It seems that the first mem
	// fd we open, very early in exec, refers to some resource
	// that's different than the one we see after reopening the
	// fd, after exec.
	if (0 == nread && 0 == errno) {
		reopen_mem_fd();
		return read_bytes_fallible(addr, buf_size, buf);
	}
	return nread;
}

void
Task::read_bytes_helper(void* addr, ssize_t buf_size, byte* buf)
{
	ssize_t nread = read_bytes_fallible(addr, buf_size, buf);
	ASSERT(this, nread == buf_size)
		<<"Should have read "<< buf_size <<" bytes from "<< addr
		<<", but only read "<< nread;
}

void
Task::write_bytes_helper(void* addr, ssize_t buf_size, const byte* buf)
{
	ASSERT(this, buf_size >= 0) <<"Invalid buf_size "<< buf_size;
	if (0 == buf_size) {
		return;
	}
	errno = 0;
	ssize_t nwritten = pwrite64(child_mem_fd, buf, buf_size,
				    to_offset(addr));
	// See comment in read_bytes_helper().
	if (0 == nwritten && 0 == errno) {
		reopen_mem_fd();
		return write_bytes_helper(addr, buf_size, buf);
	}
	ASSERT(this, nwritten == buf_size)
		<<"Should have written "<< buf_size <<" bytes to "<< addr
		<<", but only wrote "<< nwritten;
}

TraceFstream&
Task::trace_fstream()
{
	if (session_record) {
		return session_record->ofstream();
	}
	return session_replay->ifstream();
}

const TraceFstream&
Task::trace_fstream() const
{
	if (session_record) {
		return session_record->ofstream();
	}
	return session_replay->ifstream();
}

void
Task::xptrace(int request, void* addr, void* data)
{
	long ret = fallible_ptrace(request, addr, data);
	ASSERT(this, 0 == ret)
		<< "ptrace("<< ptrace_req_name(request) <<", "<< tid
		<<", addr="<< addr <<", data="<< data <<") failed";
}

/*static*/ void
Task::handle_runaway(int sig)
{
	LOG(debug) <<"SIGALRM fired; runaway tracee";
	if (!waiter || -1 != waiter->wait_status) {
		LOG(debug) <<"  ... false alarm, race condition";
		return;
	}
	waiter->xptrace(PTRACE_INTERRUPT, nullptr, nullptr);
	waiter_was_interrupted = true;
}

/*static*/ Task*
Task::os_clone(Task* parent, Session* session,
	       struct current_state_buffer* state,
	       pid_t rec_child_tid, unsigned base_flags, void* stack,
	       void* ptid, void* tls, void* ctid)
{
	// NB: reference the glibc i386 clone.S implementation for
	// placement of clone syscall args.  The man page is incorrect
	// and the linux source is confusing.
	remote_syscall5(parent, state, SYS_clone,
			base_flags, stack, ptid, tls, ctid);
	while (!(PTRACE_EVENT_CLONE == parent->ptrace_event()
		 || PTRACE_EVENT_FORK == parent->ptrace_event())) {
		ASSERT(parent, (SYSCALL_MAY_RESTART(parent->regs().syscall_result_signed())
				|| -ENOSYS == parent->regs().syscall_result_signed()))
			<<"Unexpected task status "<< HEX(parent->status())
			<<" (syscall result:"<< parent->regs().syscall_result_signed() <<")";
		parent->cont_syscall();
	}

	parent->cont_syscall();
	long new_tid = parent->regs().syscall_result_signed();
	if (0 > new_tid) {
		FATAL() <<"Failed to clone("<< parent->tid <<") -> "<< new_tid
			<< ": "<< strerror(-new_tid);
	}
	Task* child = parent->clone(clone_flags_to_task_flags(base_flags),
				    stack, tls, ctid,
				    new_tid, rec_child_tid, session);
	child->wait();
	return child;
}

/*static*/ Task*
Task::spawn(const struct args_env& ae, Session& session, pid_t rec_tid)
{
	assert(session.tasks().size() == 0);

	pid_t tid = fork();
	if (0 == tid) {
		set_up_process();
		// Signal to tracer that we're configured.
		::kill(getpid(), SIGSTOP);

		// We do a small amount of dummy work here to retire
		// some branches in order to ensure that the rbc is
		// non-zero.  The tracer can then check the rbc value
		// at the first ptrace-trap to see if it seems to be
		// working.
		int start = rand() % 5;
		int num_its = start + 5;
		int sum = 0;
		for (int i = start; i < num_its; ++i) {
			sum += i;
		}
		syscall(SYS_write, -1, &sum, sizeof(sum));

		execvpe(ae.exe_image.c_str(), ae.argv.data(), ae.envp.data());
		FATAL() <<"Failed to exec '"<< ae.exe_image.c_str() <<"'";
	}

	signal(SIGALRM, Task::handle_runaway);

	Task* t = new Task(tid, rec_tid, 0);
	// The very first task we fork inherits the signal
	// dispositions of the current OS process (which should all be
	// default at this point, but ...).  From there on, new tasks
	// will transitively inherit from this first task.
	auto sh = Sighandlers::create();
	sh->init_from_current_process();
	t->sighandlers.swap(sh);
	// Don't use the POSIX wrapper, because it doesn't necessarily
	// read the entire sigset tracked by the kernel.
	if (::syscall(SYS_rt_sigprocmask, SIG_SETMASK, NULL,
		      &t->blocked_sigs, sizeof(t->blocked_sigs))) {
		FATAL() <<"Failed to read blocked signals";
	}
	auto g = session.create_tg(t);
	t->tg.swap(g);
	auto as = session.create_vm(t, ae.exe_image);
	t->as.swap(as);

	// Sync with the child process.
	t->xptrace(PTRACE_SEIZE, nullptr,
		   (void*)(PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK |
			   PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE |
			   PTRACE_O_TRACEEXEC | PTRACE_O_TRACEVFORKDONE |
			   PTRACE_O_TRACEEXIT | PTRACE_O_TRACESECCOMP));
	// PTRACE_SEIZE is fundamentally racy by design.  We depend on
	// stopping the tracee at a known location, so raciness is
	// bad.  To resolve the race condition, we just keep running
	// the tracee until it reaches the known-safe starting point.
	//
	// Alternatively, it would be possible to remove the
	// requirement of the tracing beginning from a known point.
	while (true) {
		t->wait();
		if (SIGSTOP == t->stop_sig()) {
			break;
		}
		t->cont_nonblocking();
	}
	t->force_status(0);
	return t;

}
