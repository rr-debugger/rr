/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_COMPRESSED_IO_H_
#define RR_COMPRESSED_IO_H_

#include <pthread.h>
#include <stdint.h>

#include <memory>
#include <vector>
#include <string>

/**
 * CompressedWriter opens an output file and writes compressed blocks to it.
 * Blocks of a fixed but unspecified size (currently 1MB) are compressed.
 * Each block of compressed data is written to the file preceded by two
 * 32-bit words: the size of the compressed data (excluding block header)
 * and the size of the uncompressed data, in that order.
 *
 * We use multiple threads to perform compression. The threads are
 * responsible for the actual data writes. The thread that creates the
 * CompressedWriter is the "producer" thread and must also be the caller of
 * 'write'. The producer thread may block in 'write' if 'buffer_size' bytes are
 * being compressed.
 *
 * Each data block is compressed independently using zlib.
 */
class CompressedWriter {
public:
  CompressedWriter(const std::string& filename, size_t buffer_size,
                   uint32_t num_threads);
  ~CompressedWriter();
  // Call only on producer thread
  bool good() const { return !error; }
  // Call only on producer thread.
  void write(const void* data, size_t size);
  // Call only on producer thread
  void close();

protected:
  enum WaitFlag {
    WAIT,
    NOWAIT
  };
  void update_reservation(WaitFlag wait_flag);

  static void* compression_thread_callback(void* p);
  void compression_thread();
  size_t do_compress(uint64_t offset, size_t length, uint8_t* outputbuf,
                     size_t outputbuf_len);

  // Immutable while threads are running
  int fd;
  int block_size;
  pthread_mutex_t mutex;
  pthread_cond_t cond;
  std::vector<pthread_t> threads;

  // Carefully shared...
  std::vector<uint8_t> buffer;

  // BEGIN protected by 'mutex'
  /* position in output stream that this thread is currently working on,
   * or UINT64_MAX if it's idle */
  std::vector<uint64_t> thread_pos;
  /* position in output stream of data to dispatch to next thread */
  uint64_t next_thread_pos;
  /* position in output stream of end of data ready to dispatch */
  uint64_t next_thread_end_pos;
  bool closing;
  bool write_error;
  // END protected by 'mutex'

  /* producer thread only */
  /* Areas in the buffer that have been reserved for write() */
  uint64_t producer_reserved_pos;
  uint64_t producer_reserved_write_pos;
  uint64_t producer_reserved_upto_pos;
  bool error;
};

/**
 * CompressedReader opens an input file written by CompressedWriter
 * and reads data from it. Currently data is decompressed by the thread that
 * calls read().
 */
class CompressedReader {
public:
  CompressedReader(const std::string& filename);
  CompressedReader(const CompressedReader& aOther);
  ~CompressedReader();
  bool good() const { return !error; }
  bool at_end() const { return eof && buffer_read_pos == buffer.size(); }
  // Returns true if successful. Otherwise there's an error and good()
  // will be false.
  bool read(void* data, size_t size);
  void rewind();
  void close();

  /**
   * Save the current position. Nested saves are not allowed.
   */
  void save_state();
  /**
   * Restore previously saved position.
   */
  void restore_state();

  /**
   * Gathers stats on the file stream. These are independent of what's
   * actually been read.
   */
  uint64_t uncompressed_bytes() const;
  uint64_t compressed_bytes() const;

protected:
  /* Our fd might be the dup of another fd, so we can't rely on its current file
     position.
     Instead track the current position in fd_offset and use pread. */
  uint64_t fd_offset;
  int fd;
  bool error;
  bool eof;
  std::vector<uint8_t> buffer;
  size_t buffer_read_pos;

  bool have_saved_state;
  bool have_saved_buffer;
  uint64_t saved_fd_offset;
  std::vector<uint8_t> saved_buffer;
  size_t saved_buffer_read_pos;
};

#endif /* RR_COMPRESSED_IO_H_ */
