/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "PerfCounterBuffers.h"

#include <sys/mman.h>

#include "util.h"
#include "log.h"

using namespace std;

namespace rr {

void PerfCounterBuffers::destroy() {
  if (mmap_aux_buffer) {
    munmap(mmap_aux_buffer, mmap_header->aux_size);
    mmap_aux_buffer = nullptr;
  }
  if (mmap_header) {
    munmap(mmap_header, page_size() + buffer_size);
    mmap_header = nullptr;
  }
}

void PerfCounterBuffers::allocate(ScopedFd& perf_event_fd,
    uint64_t buffer_size, uint64_t aux_size, bool *ok) {
  this->buffer_size = buffer_size;
  if (ok) {
    *ok = true;
  }

  void* base = mmap(NULL, page_size() + buffer_size,
      PROT_READ | PROT_WRITE, MAP_SHARED, perf_event_fd, 0);
  if (base == MAP_FAILED) {
    const auto msg = "Can't allocate memory for PT DATA area";
    if (!ok) {
      FATAL() << msg;
    }
    LOG(warn) << msg;
    *ok = false;
    return;
  }
  mmap_header = static_cast<struct perf_event_mmap_page*>(base);

  if (aux_size > 0) {
    mmap_header->aux_offset = mmap_header->data_offset + mmap_header->data_size;
    mmap_header->aux_size = aux_size;

    void* aux = mmap(NULL, mmap_header->aux_size, PROT_READ | PROT_WRITE, MAP_SHARED,
        perf_event_fd, mmap_header->aux_offset);
    if (aux == MAP_FAILED) {
      const auto msg = "Can't allocate memory for PT AUX area";
      if (!ok) {
        FATAL() << msg;
      }
      LOG(warn) << msg;
      *ok = false;
      return;
    }
    mmap_aux_buffer = static_cast<char*>(aux);
  }
}

optional<PerfCounterBuffers::Packet> PerfCounterBuffers::next_packet() {
  if (packet_in_use) {
    FATAL() << "Can't offer more than one packet at a time";
  }

  // Equivalent of kernel's READ_ONCE. This value is written
  // by the kernel.
  uint64_t data_end =
    *reinterpret_cast<volatile unsigned long long*>(&mmap_header->data_head);
  if (mmap_header->data_tail >= data_end) {
    return nullopt;
  }
  // Force memory barrier to ensure that we see all memory updates that were
  // performed before `data_head `was updated.
  __sync_synchronize();

  char* data_buf = reinterpret_cast<char*>(mmap_header) + mmap_header->data_offset;
  uint64_t data_start = mmap_header->data_tail;
  size_t start_offset = data_start % mmap_header->data_size;
  auto header_ptr = reinterpret_cast<struct perf_event_header*>(data_buf + start_offset);
  struct perf_event_header header;
  memcpy(&header, header_ptr, sizeof(header));

  size_t first_chunk_size = min<size_t>(header.size,
      mmap_header->data_size - start_offset);

  if (first_chunk_size < header.size) {
    packet_storage.resize(header.size);
    memcpy(packet_storage.data(), const_cast<perf_event_header*>(header_ptr), first_chunk_size);
    memcpy(packet_storage.data() + first_chunk_size, const_cast<char*>(data_buf), header.size - first_chunk_size);
    header_ptr = reinterpret_cast<struct perf_event_header*>(packet_storage.data());
  }

  void* aux_ptr = nullptr;
  if (header.type == PERF_RECORD_AUX) {
    PerfEventAux aux_packet = *reinterpret_cast<PerfEventAux*>(header_ptr);
    size_t aux_start_offset = aux_packet.aux_offset % mmap_header->aux_size;
    aux_ptr = mmap_aux_buffer + aux_start_offset;
    first_chunk_size = min<size_t>(aux_packet.aux_size, mmap_header->aux_size - aux_start_offset);
    if (first_chunk_size < aux_packet.aux_size) {
      aux_packet_storage.resize(aux_packet.aux_size);
      memcpy(aux_packet_storage.data(), aux_ptr, first_chunk_size);
      memcpy(aux_packet_storage.data() + first_chunk_size, mmap_aux_buffer,
             aux_packet.aux_size - first_chunk_size);
      aux_ptr = aux_packet_storage.data();
    }
    packet_data_aux_end = mmap_header->aux_tail + aux_packet.aux_size;
  }

  packet_in_use = true;
  packet_data_end = data_start + header.size;
  return Packet(*this, header_ptr, aux_ptr);
}

void PerfCounterBuffers::release_packet() {
  if (!packet_in_use) {
    FATAL() << "No packet!";
  }
  mmap_header->data_tail = packet_data_end;
  mmap_header->aux_tail = packet_data_aux_end;
  packet_in_use = false;
}

}
