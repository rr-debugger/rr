/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#define _LARGEFILE64_SOURCE

#include "CompressedReader.h"

#include <brotli/decode.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "CompressedWriter.h"
#include "core.h"
#include "util.h"

using namespace std;

namespace rr {

CompressedReader::CompressedReader(const string& filename)
    : fd(new ScopedFd(filename.c_str(), O_CLOEXEC | O_RDONLY | O_LARGEFILE)) {
  fd_offset = 0;
  error = !fd->is_open();
  if (error) {
    eof = false;
  } else {
    char ch;
    eof = pread(*fd, &ch, 1, fd_offset) == 0;
  }
  buffer_read_pos = 0;
  have_saved_state = false;
}

CompressedReader::CompressedReader(const CompressedReader& other) {
  fd = other.fd;
  fd_offset = other.fd_offset;
  error = other.error;
  eof = other.eof;
  buffer_read_pos = other.buffer_read_pos;
  buffer = other.buffer;
  have_saved_state = false;
  DEBUG_ASSERT(!other.have_saved_state);
}

CompressedReader::~CompressedReader() { close(); }

static bool read_all(const ScopedFd& fd, size_t size, void* data,
                     uint64_t* offset) {
  ssize_t ret = read_to_end(fd, *offset, data, size);
  if (ret == (ssize_t)size) {
    *offset += size;
    return true;
  }
  return false;
}

static bool do_decompress(std::vector<uint8_t>& compressed,
                          std::vector<uint8_t>& uncompressed) {
  size_t out_size = uncompressed.size();
  return BrotliDecoderDecompress(compressed.size(), compressed.data(),
                                 &out_size, uncompressed.data()) ==
             BROTLI_DECODER_RESULT_SUCCESS &&
         out_size == uncompressed.size();
}

bool CompressedReader::get_buffer(const uint8_t** data, size_t* size) {
  if (error) {
    return false;
  }

  if (buffer_read_pos >= buffer.size() && !eof) {
    if (!refill_buffer()) {
      return false;
    }
    DEBUG_ASSERT(buffer_read_pos < buffer.size());
  }

  *data = &buffer[buffer_read_pos];
  *size = buffer.size() - buffer_read_pos;
  return true;
}

bool CompressedReader::skip(size_t size) {
  while (size > 0) {
    if (error) {
      return false;
    }

    if (buffer_read_pos < buffer.size()) {
      size_t amount = std::min(size, buffer.size() - buffer_read_pos);
      size -= amount;
      buffer_read_pos += amount;
      continue;
    }

    if (!refill_buffer()) {
      return false;
    }
  }
  return true;
}

bool CompressedReader::read(void* data, size_t size) {
  while (size > 0) {
    if (error) {
      return false;
    }

    if (buffer_read_pos < buffer.size()) {
      size_t amount = std::min(size, buffer.size() - buffer_read_pos);
      memcpy(data, &buffer[buffer_read_pos], amount);
      size -= amount;
      data = static_cast<char*>(data) + amount;
      buffer_read_pos += amount;
      continue;
    }

    if (!refill_buffer()) {
      return false;
    }
  }
  return true;
}

bool CompressedReader::refill_buffer() {
  if (have_saved_state && !have_saved_buffer) {
    std::swap(buffer, saved_buffer);
    have_saved_buffer = true;
  }

  CompressedWriter::BlockHeader header;
  if (!read_all(*fd, sizeof(header), &header, &fd_offset)) {
    error = true;
    return false;
  }

  std::vector<uint8_t> compressed_buf;
  compressed_buf.resize(header.compressed_length);
  if (!read_all(*fd, compressed_buf.size(), &compressed_buf[0], &fd_offset)) {
    error = true;
    return false;
  }

  char ch;
  if (pread(*fd, &ch, 1, fd_offset) == 0) {
    eof = true;
  }

  buffer.resize(header.uncompressed_length);
  buffer_read_pos = 0;
  if (!do_decompress(compressed_buf, buffer)) {
    error = true;
    return false;
  }

  return true;
}

void CompressedReader::rewind() {
  DEBUG_ASSERT(!have_saved_state);
  fd_offset = 0;
  buffer_read_pos = 0;
  buffer.clear();
  eof = false;
}

void CompressedReader::close() { fd = nullptr; }

void CompressedReader::save_state() {
  DEBUG_ASSERT(!have_saved_state);
  have_saved_state = true;
  have_saved_buffer = false;
  saved_fd_offset = fd_offset;
  saved_buffer_read_pos = buffer_read_pos;
}

void CompressedReader::restore_state() {
  DEBUG_ASSERT(have_saved_state);
  have_saved_state = false;
  if (saved_fd_offset < fd_offset) {
    eof = false;
  }
  fd_offset = saved_fd_offset;
  if (have_saved_buffer) {
    std::swap(buffer, saved_buffer);
    saved_buffer.clear();
  }
  buffer_read_pos = saved_buffer_read_pos;
}

void CompressedReader::discard_state() {
  DEBUG_ASSERT(have_saved_state);
  have_saved_state = false;
  if (have_saved_buffer) {
    saved_buffer.clear();
  }
}

uint64_t CompressedReader::uncompressed_bytes() const {
  uint64_t offset = 0;
  uint64_t uncompressed_bytes = 0;
  CompressedWriter::BlockHeader header;
  while (read_all(*fd, sizeof(header), &header, &offset)) {
    uncompressed_bytes += header.uncompressed_length;
    offset += header.compressed_length;
  }
  return uncompressed_bytes;
}

uint64_t CompressedReader::compressed_bytes() const {
  return lseek(*fd, 0, SEEK_END);
}

} // namespace rr
