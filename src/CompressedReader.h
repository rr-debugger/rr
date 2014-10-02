/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_COMPRESSED_READER_H_
#define RR_COMPRESSED_READER_H_

#include <pthread.h>
#include <stdint.h>

#include <memory>
#include <vector>
#include <string>

#include "ScopedFd.h"

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
  std::shared_ptr<ScopedFd> fd;
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

#endif /* RR_COMPRESSED_READER_H_ */
