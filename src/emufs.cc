/* -*- mode: C++; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

//#define DEBUGTAG "EmuFs"

#include "emufs.h"

#include <syscall.h>

#include <sstream>
#include <string>

#include "log.h"
#include "session.h"

using namespace std;

static void replace_char(string& s, char c, char replacement)
{
	size_t i;
	while (string::npos != (i = s.find(c))) {
		s[i] = replacement;
	}
}

EmuFile::~EmuFile()
{
	LOG(debug) <<"    EmuFs::~File(einode:"<< est.st_ino <<")";
}

void
EmuFile::update(const struct stat& st)
{
	assert(est.st_dev == st.st_dev && est.st_ino == st.st_ino);
	if (est.st_size != st.st_size) {
		resize_shmem_segment(file, st.st_size);
	}
	est = st;
}

/*static*/ EmuFile::shr_ptr
EmuFile::create(const char* orig_path, const struct stat& est)
{
	// Sanitize the mapped file path so that we can use it in a
	// leaf name.
	string tag(orig_path);
	replace_char(tag, '/', '\\');

	stringstream name;
	name << "rr-emufs-"<< getpid() <<"-dev-" << est.st_dev
	     << "-inode-" << est.st_ino << "-" << tag;
	shr_ptr f(new EmuFile(create_shmem_segment(name.str().c_str(),
						   est.st_size), est));
	LOG(debug) <<"created emulated file for "<< orig_path
		   <<" as "<< name.str();
	return f;
}

void
EmuFs::gc()
{
	// XXX this implementation is unnecessarily slow.  But before
	// throwing it away for something different, give it another
	// shot once rr is caching local mmaps for all address spaces,
	// which obviates the need for the yuck slow maps parsing
	// here.
	LOG(debug) <<"Beginning emufs gc of "<< files.size() <<" files";

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
	for (auto as : Session::current()->vms()) {
		Task* t = *as->task_set().begin();
		LOG(debug) <<"  iterating /proc/"<< t->tid <<"/maps ...";

		mark_used_vfiles(t, *as, &nr_marked_files);
		if (files.size() == nr_marked_files) {
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
	for (auto it = files.begin(); it != files.end(); ++it) {
		if (!it->second->marked()) {
			garbage.push_back(it->first);
		}
		it->second->unmark();
	}
	for (auto it = garbage.begin(); it != garbage.end(); ++it) {
		LOG(debug) <<"  emufs gc reclaiming einode:"<< it->inode;
		files.erase(*it);
	}
}

int
EmuFs::get_or_create(const struct mmapped_file& mf)
{
	auto it = files.find(mf.stat);
	if (it != files.end()) {
		it->second->update(mf.stat);
		return it->second->fd();
	}
	auto vf = EmuFile::create(mf.filename, mf.stat);
	files[mf.stat] = vf;
	return vf->fd();
}

void
EmuFs::mark_used_vfiles(Task* t, const AddressSpace& as,
			size_t* nr_marked_files)
{
	for (auto it = as.begin(); it != as.end(); ++it) {
		const MappableResource& r = it->second;
		LOG(debug) <<"  examining "<< r.fsname.c_str() <<" ...";

		auto id_ef = files.find(r.id);
		if (id_ef == files.end()) {
			continue;
		}
		auto ef = id_ef->second;
		if (!ef->marked()) {
			ef->mark();
			LOG(debug) <<"    marked einode:"<< r.id.inode;
			++*nr_marked_files;
			if (files.size() == *nr_marked_files) {
				LOG(debug) <<"  (marked all files, bailing)";
				return;
			}
		}
	}
}

AutoGc::AutoGc(EmuFs& fs, int syscallno, int state)
	: fs(fs)
	, is_gc_point(fs.size() > 0
		      && STATE_SYSCALL_EXIT == state
		      && (SYS_close == syscallno
			  || SYS_munmap == syscallno)) {
	if (is_gc_point) {
		LOG(debug) <<"emufs gc required because of syscall `"
			   << syscallname(syscallno) <<"'";
	}
}

AutoGc::~AutoGc() {
	if (is_gc_point) {
		fs.gc();
	}
}
