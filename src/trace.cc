/* -*- Mode: C++; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

//#define DEBUGTAG "Trace"

#include "trace.h"

#include <sysexits.h>

#include <fstream>
#include <string>
#include <sstream>

#include "log.h"
#include "util.h"

using namespace std;

//
// This represents the format and layout of recorded traces.  This
// version number doesn't track the rr version number, because changes
// to the trace format will be rare.
//
// NB: if you *do* change the trace format for whatever reason, you
// MUST increment this version number.  Otherwise users' old traces
// will become unreplayable and they won't know why.
//
#define TRACE_VERSION 2

static ssize_t sizeof_trace_frame_event_info(void)
{
	return offsetof(struct trace_frame, end_event_info) -
		offsetof(struct trace_frame, begin_event_info);
}

static ssize_t sizeof_trace_frame_exec_info(void)
{
	return offsetof(struct trace_frame, end_exec_info) -
		offsetof(struct trace_frame, begin_exec_info);
}

static string default_rr_trace_dir()
{
	return string(getenv("HOME")) + "/.rr";
}

static string trace_save_dir()
{
	const char* output_dir = getenv("_RR_TRACE_DIR");
	return output_dir ? output_dir : default_rr_trace_dir();
}

static string latest_trace_symlink()
{
	return trace_save_dir() + "/latest-trace";
}

/**
 * Create the default ~/.rr directory if it doesn't already exist.
 */
static void ensure_default_rr_trace_dir()
{
	string dir = default_rr_trace_dir();
	struct stat st;
	if (0 == stat(dir.c_str(), &st)) {
		if (!(S_IFDIR & st.st_mode)) {
			FATAL() <<"`"<< dir <<"' exists but isn't a directory.";
		}
		if (access(dir.c_str(), W_OK)) {
			FATAL() <<"Can't write to `"<< dir <<"'.";
		}
		return;
	}
	int ret = mkdir(dir.c_str(), S_IRWXU | S_IRWXG);
	int err = errno;
	// Another rr process can be concurrently attempting to create
	// ~/.rr, so the directory may have come into existence since
	// we checked above.
	if (ret && EEXIST != err) {
		FATAL() <<"Failed to create directory `"<< dir <<"'";
	}
}

void
trace_frame::dump(FILE* out, bool raw_dump)
{
	out = out ? out : stdout;
	const struct user_regs_struct& r = recorded_regs;

	if (raw_dump) {
		fprintf(out, " %d %d %d %d",
			global_time, thread_time, tid, ev.encoded);
	} else {
		fprintf(out,
"{\n  global_time:%u, event:`%s' (state:%d), tid:%d, thread_time:%u",
			global_time, Event(ev).str().c_str(),
			ev.state, tid, thread_time);
	}
	if (!ev.has_exec_info) {
		if (!raw_dump) {
			fprintf(out, "\n}");
		}
		fprintf(out, "\n");
		return;
	}

	if (raw_dump) {
		fprintf(out,
			" %lld %lld %lld %lld"
			" %ld %ld %ld %ld %ld %ld %ld"
			" %ld %ld %ld %ld\n",
#ifdef HPC_ENABLE_EXTRA_PERF_COUNTERS
			hw_interrupts, page_faults, rbc, insts,
#else
			// Don't force tools to detect our config.
			-1LL, -1LL, rbc, -1LL,
#endif
			r.eax, r.ebx, r.ecx, r.edx, r.esi, r.edi, r.ebp,
			r.orig_eax, r.esp, r.eip, r.eflags);
	} else {
		fprintf(out,
"\n"
#ifdef HPC_ENABLE_EXTRA_PERF_COUNTERS
"  hw_ints:%lld faults:%lld rbc:%lld insns:%lld\n"
#else
"  rbc:%lld\n"
#endif
"  eax:0x%lx ebx:0x%lx ecx:0x%lx edx:0x%lx esi:0x%lx edi:0x%lx ebp:0x%lx\n"
"  eip:0x%lx esp:0x%lx eflags:0x%lx orig_eax:%ld xfs:0x%lx xgs:0x%lx\n"
"}\n",
#ifdef HPC_ENABLE_EXTRA_PERF_COUNTERS
			hw_interrupts, page_faults, rbc, insts,
#else
			rbc,
#endif
			r.eax, r.ebx, r.ecx, r.edx, r.esi, r.edi, r.ebp,
			r.eip, r.esp, r.eflags, r.orig_eax, r.xfs, r.xgs);
	}
}

args_env::args_env(int argc, char* arg_v[], char** env_p)
	: exe_image(arg_v[0])
{
	for (int i = 0; i < argc; ++i) {
		argv.push_back(strdup(arg_v[i]));
	}
	argv.push_back(nullptr);
	for (; *env_p; ++env_p) {
		envp.push_back(strdup(*env_p));
	}
	envp.push_back(nullptr);
}

args_env::~args_env()
{
	destroy();
}

args_env&
args_env::operator=(args_env&& o)
{
	swap(exe_image, o.exe_image);
	swap(argv, o.argv);
	swap(envp, o.envp);
	return *this;
}

void
args_env::destroy()
{
	for (size_t i = 0; i < argv.size(); ++i) {
		free(argv[i]);
	}
	for (size_t i = 0; i < envp.size(); ++i) {
		free(envp[i]);
	}
}

bool
TraceFstream::good() const
{
	return (events.good()
		&& data.good() && data_header.good()
		&& mmaps.good());
}

string
TraceFstream::args_env_file_path() const
{
	return trace_dir + "/args_env";
}

string
TraceFstream::version_file_path() const
{
	return trace_dir + "/version";
}

TraceOfstream& operator<<(TraceOfstream& tof, const struct trace_frame& frame)
{
	const char* begin_data = (const char*)&frame.begin_event_info;
	ssize_t nbytes = sizeof_trace_frame_event_info();

	// TODO: only store exec info for non-async-sig events when
	// debugging assertions are enabled.
	if (frame.ev.has_exec_info) {
		nbytes += sizeof_trace_frame_exec_info();
	}
	tof.events.write(begin_data, nbytes);
	if (!tof.events.good()) {
		FATAL() <<"Tried to save "<< nbytes <<" bytes to the trace, but failed";
	}
	tof.tick_time();
	return tof;
}
TraceIfstream& operator>>(TraceIfstream& tif, struct trace_frame& frame)
{
	memset(&frame, 0, sizeof(frame));
	// Read the common event info first, to see if we also have
	// exec info to read.
	tif.events.read((char*)&frame.begin_event_info,
			sizeof_trace_frame_event_info());
	if (frame.ev.has_exec_info) {
		tif.events.read((char*)&frame.begin_exec_info,
				sizeof_trace_frame_exec_info());
	}
	tif.tick_time();
	assert(tif.time() == frame.global_time);
	// Set the eofbit if we're at end-of-stream.
	tif.events.peek();
	return tif;
}

static ostream& operator<<(ostream& out, const struct timespec& ts)
{
	out << ts.tv_sec <<" "<< ts.tv_nsec;
	return out;
}
static istream& operator>>(istream& in, struct timespec& ts)
{
	in >> ts.tv_sec >> ts.tv_nsec;
	return in;
}

static ostream& operator<<(ostream& out, const struct stat& v)
{
	out << v.st_blksize <<" "<< v.st_blocks <<" "<< v.st_ctim
	    <<" "<< v.st_dev <<" "<< v.st_gid <<" "<< v.st_ino
	    <<" "<< v.st_mode <<" "<< v.st_mtim <<" "<< v.st_mtim.tv_nsec
	    <<" "<< v.st_rdev <<" "<< v.st_size <<" "<< v.st_uid;
	return out;
}
static istream& operator>>(istream& in, struct stat& v)
{
	in >> v.st_blksize >> v.st_blocks >> v.st_ctim
	    >> v.st_dev >> v.st_gid >> v.st_ino
	    >> v.st_mode >> v.st_mtim >> v.st_mtim.tv_nsec
	    >> v.st_rdev >> v.st_size >> v.st_uid;
	return in;
}

TraceOfstream& operator<<(TraceOfstream& tof, const struct mmapped_file& map)
{
	tof.mmaps << map.time <<" "<< map.tid <<" "<< map.copied
		  <<" "<< map.filename <<'\0'
		  <<" "<< map.stat <<" "<< map.start <<" "<< map.end << endl;
	return tof;
}
TraceIfstream& operator>>(TraceIfstream& tif, struct mmapped_file& map)
{
	tif.mmaps >> map.time >> map.tid >> map.copied;
	tif.mmaps.ignore(1);
	tif.mmaps.getline(map.filename, sizeof(map.filename), '\0');
	tif.mmaps >> map.stat >> map.start >> map.end;
	return tif;
}

static ostream& operator<<(ostream& out, const CharpVector& v)
{
	assert(!v.back());
	out << v.size() - 1 << endl;
	for (auto it = v.begin(); *it && it != v.end(); ++it) {
		out << *it << '\0';
	}
	return out;
}
static istream& operator>>(istream& in, CharpVector& v)
{
	size_t len;
	in >> len;
	in.ignore(1);
	v.reserve(len + 1);
	for (size_t i = 0; i < len; ++i) {
		char buf[PATH_MAX];
		in.getline(buf, sizeof(buf), '\0');
		v.push_back(strdup(buf));
	}
	v.push_back(nullptr);
	return in;
}

TraceOfstream& operator<<(TraceOfstream& tof, const struct args_env& ae)
{
	ofstream out(tof.args_env_file_path());

	assert(out.good());


	out << ae.argv;
	out << ae.envp;
	return tof;
}
TraceIfstream& operator>>(TraceIfstream& tif, struct args_env& ae)
{
	ifstream in(tif.args_env_file_path());

	assert(in.good());

	in >> ae.argv;

	assert(in.good());

	ae.exe_image = ae.argv[0];
	in >> ae.envp;
	return tif;
}

TraceOfstream& operator<<(TraceOfstream& tof, const struct raw_data& d)
{
	tof.data_header << d.global_time <<" "<< d.ev.encoded
			<<" "<< d.addr <<" "<< d.data.size() << endl;
	tof.data.write((const char*)d.data.data(), d.data.size());
	return tof;
}
TraceIfstream& operator>>(TraceIfstream& tif, struct raw_data& d)
{
	size_t num_bytes;
	tif.data_header >> d.global_time >> d.ev.encoded >> d.addr
			>> num_bytes;
	d.data.resize(num_bytes);
	tif.data.read((char*)d.data.data(), num_bytes);
	return tif;
}

void
TraceOfstream::flush()
{
	events.flush();
	data.flush();
	data_header.flush();
	mmaps.flush();
}

/*static*/ TraceOfstream::shr_ptr
TraceOfstream::create(const string& exe_path)
{
	ensure_default_rr_trace_dir();

	// Find a unique trace directory name.
	int nonce = 0;
	int ret;
	string dir;
	do {
		stringstream ss;
		ss << trace_save_dir() << "/" << basename(exe_path.c_str())
		   << "-" << nonce++;
		dir = ss.str();
		ret = mkdir(dir.c_str(), S_IRWXU | S_IRWXG);
	} while (ret && EEXIST == errno);

	if (ret) {
		FATAL() <<"Unable to create trace directory `"<< dir <<"'";
	}

	shr_ptr trace(new TraceOfstream(dir));

	string version_path = trace->version_file_path();
	fstream version(version_path.c_str(), fstream::out);
	if (!version.good()) {
		FATAL() <<"Unable to create "<< version_path;
	}
	version << TRACE_VERSION << endl;

	string link_name = latest_trace_symlink();
	// Try to update the symlink to |trace|.  We only try attempt
	// to set the symlink once.  If the link is re-created after
	// we |unlink()| it, then another rr process is racing with us
	// and it "won".  The link is then valid and points at some
	// very-recent trace, so that's good enough.
	unlink(link_name.c_str());
	ret = symlink(trace->trace_dir.c_str(), link_name.c_str());
	if (!(0 == ret || EEXIST == ret)) {
		FATAL() <<"Failed to update symlink `"<< link_name
			<<"' to `"<< trace->trace_dir <<"'.";
	}

	if (!probably_not_interactive(STDOUT_FILENO)) {
		printf(
"rr: Saving the execution of `%s' to trace directory `%s'.\n",
			exe_path.c_str(), trace->trace_dir.c_str());
	}
	return trace;
}

struct AutoRestoreState {
	AutoRestoreState(TraceIfstream& ifs)
		: ifs(ifs)
		, pos(ifs.events.tellg())
		, global_time(ifs.global_time)
	{}
	~AutoRestoreState() {
		ifs.events.seekg(pos);
		ifs.global_time = global_time;
	}
	TraceIfstream& ifs;
	fstream::streampos pos;
	uint32_t global_time;
};

struct trace_frame
TraceIfstream::peek_frame()
{
	AutoRestoreState restore(*this);
	struct trace_frame frame;
	*this >> frame;
	return frame;
}

struct trace_frame
TraceIfstream::peek_to(pid_t pid, EventType type, int state)
{
	AutoRestoreState restore(*this);
	struct trace_frame frame;
	while (good()) {
		*this >> frame;
		if (frame.tid == pid
		    && frame.ev.type == type
		    && frame.ev.state == state) {
			return frame;
		}
	}
	FATAL() <<"Unable to find requested frame in stream";
	// Unreachable
	return frame;
}

void
TraceIfstream::rewind()
{
	events.seekg(0);
	data.seekg(0);
	data_header.seekg(0);
	mmaps.seekg(0);
	global_time = 0;
	assert(good());
}

/*static*/ TraceIfstream::shr_ptr
TraceIfstream::open(int argc, char** argv)
{
	shr_ptr trace(new TraceIfstream(0 == argc ?
					latest_trace_symlink() : argv[0]));
	string path = trace->version_file_path();
	fstream vfile(path.c_str(), fstream::in);
	if (!vfile.good()) {
		fprintf(stderr,
"\n"
"rr: error: Version file for recorded trace `%s' not found.  Did you record\n"
"           `%s' with an older version of rr?  If so, you'll need to replay\n"
"           `%s' with that older version.  Otherwise, your trace is\n"
"           likely corrupted.\n"
"\n",
			path.c_str(), path.c_str(), path.c_str());
		exit(EX_DATAERR);
	}
	int version = 0;
	vfile >> version;
	if (vfile.fail() || TRACE_VERSION != version) {
		fprintf(stderr,
"\n"
"rr: error: Recorded trace `%s' has an incompatible version %d; expected\n"
"           %d.  Did you record `%s' with an older version of rr?  If so,\n"
"           you'll need to replay `%s' with that older version.  Otherwise,\n"
"           your trace is likely corrupted.\n"
"\n",
			path.c_str(), version, TRACE_VERSION,
			path.c_str(), path.c_str());
		exit(EX_DATAERR);
	}
	return trace;
}
