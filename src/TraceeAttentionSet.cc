/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "TraceeAttentionSet.h"

#include <pthread.h>
#include <signal.h>
#include <sys/signalfd.h>
#include <unistd.h>

#include "log.h"

using namespace std;

namespace rr {

static pthread_mutex_t attention_set_lock = PTHREAD_MUTEX_INITIALIZER;
static unordered_set<pid_t>* attention_set;
static sigset_t original_mask;

static void* tracee_attention_set_thread(__attribute__((unused)) void* p) {
  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, SIGCHLD);
  int fd = signalfd(-1, &set, SFD_CLOEXEC);
  if (fd < 0) {
    FATAL() << "Can't open signalfd";
  }

  while (true) {
    struct signalfd_siginfo si;
    ssize_t ret = ::read(fd, &si, sizeof(si));
    if (ret < (ssize_t)sizeof(si)) {
      FATAL() << "Failed to read correct number of bytes: " << ret;
    }

    pthread_mutex_lock(&attention_set_lock);
    attention_set->insert(si.ssi_pid);
    pthread_mutex_unlock(&attention_set_lock);
  }
}

void TraceeAttentionSet::initialize() {
  pthread_mutex_lock(&attention_set_lock);
  if (attention_set) {
    pthread_mutex_unlock(&attention_set_lock);
    return;
  }
  attention_set = new unordered_set<pid_t>();
  // Block all signals so when we create our child thread,
  // it has all signals blocked. This also initializes original_mask.
  sigset_t set;
  sigfillset(&set);
  sigprocmask(SIG_BLOCK, &set, &original_mask);
  pthread_mutex_unlock(&attention_set_lock);

  pthread_t thread;
  pthread_create(&thread, nullptr, tracee_attention_set_thread, nullptr);
  pthread_setname_np(thread, "TraceeAttention");

  // Restore original sigmask but block SIGCHLD in this thread
  // (and all future spawned threads) so that our attention thread
  // gets all the SIGCHLD notifications via signalfd.
  sigorset(&set, &original_mask, &original_mask);
  sigdelset(&set, SIGCHLD);
  sigprocmask(SIG_SETMASK, &set, nullptr);
}

unordered_set<pid_t> TraceeAttentionSet::read() {
  unordered_set<pid_t> result;
  pthread_mutex_lock(&attention_set_lock);
  if (!attention_set) {
    FATAL() << "TraceeAttentionSet not initialized";
  }
  result = move(*attention_set);
  pthread_mutex_unlock(&attention_set_lock);
  return result;
}

void TraceeAttentionSet::get_original_sigmask(sigset_t* out) {
  pthread_mutex_lock(&attention_set_lock);
  if (attention_set) {
    sigorset(out, &original_mask, &original_mask);
  } else {
    sigprocmask(SIG_BLOCK, nullptr, out);
  }
  pthread_mutex_unlock(&attention_set_lock);
}

} // namespace rr
