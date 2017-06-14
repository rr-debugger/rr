/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_COMPRESSED_WRITER_H_
#define RR_COMPRESSED_WRITER_H_

#include <pthread.h>
#include <stdint.h>

#include <memory>
#include <string>
#include <vector>

#include "ScopedFd.h"

namespace rr {

/**
 * CompressedWriter opens an output file and writes compressed blocks to it.
 * Blocks of a fixed but unspecified size (currently 1MB) are compressed.
 * Each block of compressed data is written to the file preceded by two
 * 32-bit words: the size of the compressed data (excluding block header)
 * and the size of the uncompressed data, in that order. See BlockHeader below.
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
  enum Sync { DONT_SYNC, SYNC };
  // Call only on producer thread
  void close(Sync sync = DONT_SYNC);

  struct BlockHeader {
    uint32_t compressed_length;
    uint32_t uncompressed_length;
  };

  template <typename T> CompressedWriter& operator<<(const T& value) {
    write(&value, sizeof(value));
    return *this;
  }

  CompressedWriter& operator<<(const std::string& value) {
    write(value.c_str(), value.size() + 1);
    return *this;
  }

  template <typename T>
  CompressedWriter& operator<<(const std::vector<T>& value) {
    *this << value.size();
    for (auto& i : value) {
      *this << i;
    }
    return *this;
  }

protected:
  enum WaitFlag { WAIT, NOWAIT };
  void update_reservation(WaitFlag wait_flag);

  static void* compression_thread_callback(void* p);
  void compression_thread();
  size_t do_compress(uint64_t offset, size_t length, uint8_t* outputbuf,
                     size_t outputbuf_len);

  // Immutable while threads are running
  ScopedFd fd;
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

} // namespace rr

#endif /* RR_COMPRESSED_WRITER_H_ */
