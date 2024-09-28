/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_PERF_COUNTER_BUFFERS_H_
#define RR_PERF_COUNTER_BUFFERS_H_

#include <stdint.h>

#include <optional>

#include <linux/perf_event.h>

#include "ScopedFd.h"

namespace rr {

// I wish I knew why this type isn't defined in perf_event.h but is just
// commented out there...
struct PerfEventAux {
  struct perf_event_header header;
  uint64_t aux_offset;
  uint64_t aux_size;
  uint64_t flags;
  uint64_t sample_id;
};

/**
 * Encapsulates the mmap buffers used for perf events.
 */
class PerfCounterBuffers {
public:
  PerfCounterBuffers() : mmap_header(nullptr), mmap_aux_buffer(nullptr),
      buffer_size(0), packet_in_use(false) {}
  ~PerfCounterBuffers() { destroy(); }

  void allocate(ScopedFd& perf_event_fd, uint64_t buffer_size, uint64_t aux_size, bool *ok = nullptr);
  void destroy();

  bool allocated() const { return mmap_header != nullptr; }

  class Packet {
  public:
    Packet(Packet&& other) : buffers(other.buffers), data_(other.data_),
        aux_data_(other.aux_data_) {
      other.buffers = nullptr;
    }
    ~Packet() {
      if (buffers) {
        buffers->release_packet();
      }
    }
    struct perf_event_header* data() const { return data_; }
    void* aux_data() const { return aux_data_; }

  private:
    friend class PerfCounterBuffers;

    Packet(PerfCounterBuffers& buffers, struct perf_event_header* data,
        void* aux_data)
      : buffers(&buffers), data_(data), aux_data_(aux_data) {}

    PerfCounterBuffers* buffers;
    struct perf_event_header* data_;
    void* aux_data_;
  };

  std::optional<Packet> next_packet();

private:
  friend class Packet;

  void release_packet();

  perf_event_mmap_page* mmap_header;
  char* mmap_aux_buffer;
  uint64_t buffer_size;
  uint64_t packet_data_end;
  uint64_t packet_data_aux_end;
  std::vector<uint8_t> packet_storage;
  std::vector<uint8_t> aux_packet_storage;
  bool packet_in_use;
};

} // namespace rr

#endif /* RR_PERF_COUNTER_BUFFERS_H_ */
