/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "WaitManager.h"

#include <errno.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <map>

#include "log.h"
#include "util.h"

using namespace std;

namespace rr {

class WaitState {
public:
  WaitResult wait(const WaitOptions& options, int type);
  void poll_stops();
protected:
  // Poll child(ren) for a wait status. If tid == -1 we wait for any child, otherwise
  // we wait for the specific child 'tid' (which may be more efficient, the kernel
  // has a fast path when the child is specified).
  // If we got a status, returns the pid_t of the task we got a status for and
  // stores the status in `status`. If there's no error, there are children, but
  // none of them are reporting a status, returns 0. Otherwise returns -1 and errno
  // has been set by waitid.
  // It is possible for tid to be > 0 and for this to return a different pid, in one case:
  // when the task changes its tid due to execve handling.
  // If consume is false we don't consume the event in the kernel.
  pid_t do_wait(pid_t tid, bool consume, int type, double block_seconds, WaitStatus& status);
  bool check_status(pid_t tid, bool consume, WaitResult& result);

  map<pid_t, vector<WaitStatus>> stop_statuses;
};

pid_t WaitState::do_wait(pid_t tid, bool consume, int type, double block_seconds, WaitStatus& status) {
  int options = type | __WALL;
  if (!consume) {
    options |= WNOWAIT;
  }
  siginfo_t siginfo;
  memset(&siginfo, 0, sizeof(siginfo));
  if (block_seconds <= 0.0) {
    options |= WNOHANG;
  } else if (block_seconds < static_cast<double>(WAIT_BLOCK_MAX)) {
    struct itimerval timer = { { 0, 0 }, to_timeval(block_seconds) };
    if (setitimer(ITIMER_REAL, &timer, nullptr) < 0) {
      FATAL() << "Failed to set itimer";
    }
    LOG(debug) << "  Arming timer for polling";
    // XXX what if the timer fires before we get into waitid???
  }
  int ret = waitid(tid >= 0 ? P_PID : P_ALL, tid, &siginfo, options);
  if (ret && errno == EINVAL) {
    CLEAN_FATAL() << "waitid(options=" << options
      << ") returned EINVAL; rr requires Linux kernel 4.7 or greater";
  }
  if (!(block_seconds <= 0.0) && block_seconds < static_cast<double>(WAIT_BLOCK_MAX)) {
    int err = errno;
    struct itimerval timer = { { 0, 0 }, { 0, 0 } };
    if (setitimer(ITIMER_REAL, &timer, nullptr) < 0) {
      FATAL() << "Failed to set itimer";
    }
    LOG(debug) << "  Disarming timer for polling";
    errno = err;
  }
  if (!ret) {
    if (!siginfo.si_pid) {
      return 0;
    }
    status = WaitStatus(siginfo);
    return siginfo.si_pid;
  }
  return -1;
}

bool WaitState::check_status(pid_t tid, bool consume, WaitResult& result) {
  map<pid_t, vector<WaitStatus>>::iterator it;
  if (tid < 0) {
    it = stop_statuses.begin();
  } else {
    it = stop_statuses.find(tid); 
  }
  if (it != stop_statuses.end()) {
    result.code = WAIT_OK;
    result.tid = it->first;
    result.status = it->second[0];
    if (consume) {
      it->second.erase(it->second.begin());
      if (it->second.empty()) {
        stop_statuses.erase(it);
      }
    }
    return true;
  }
  return false;
}

WaitResult WaitState::wait(const WaitOptions& options, int type) {
  WaitResult result;
  if ((type & WSTOPPED) && check_status(options.tid, options.consume, result)) {
    return result;
  }
  if (!options.can_perform_syscall) {
    result.code = WAIT_NO_STATUS;
    return result;
  }

  pid_t ret = do_wait(options.unblock_on_other_tasks ? -1 : options.tid,
                      options.consume, type, options.block_seconds,
                      result.status);
  if (ret == 0) {
    result.code = WAIT_NO_STATUS;
    return result;
  }
  if (ret < 0) {
    if (errno == EINTR) {
      result.code = WAIT_NO_STATUS;
      return result;        
    }
    if (errno == ECHILD) {
      result.code = WAIT_NO_CHILD;
      return result;
    }
    FATAL() << "Unexpected error waiting for " << options.tid;
  }
  // We got a status for some task.

  if (options.unblock_on_other_tasks && options.tid >= 0 &&
      ret != options.tid) {
    // We got a status for a non-requested task. Stash it and return.
    if (result.status.reaped()) {
      FATAL() << "Expected a stop!";
    }
    if (options.consume) {
      // We told the kernel to consume it, so we need to store it here
      // so we can still return it when required.
      stop_statuses[ret].push_back(result.status);
    }
    result.code = WAIT_NO_STATUS;
    return result;
  }

  if (!result.status.reaped() && !(type & WSTOPPED)) {
    // We got a stop, but we weren't expecting a stop. This happens
    // because when ptrace is enabled, waitid(WEXITED) still returns
    // stops as well as exits :-(.
    if (options.consume) {
      // We told the kernel to consume it, so we need to store it here
      // so we can still return it when required.
      stop_statuses[ret].push_back(result.status);
    }
    result.code = WAIT_NO_STATUS;
    return result;
  }

  // We got a status that we should return.
  result.code = WAIT_OK;
  result.tid = ret;
  return result;
}

void WaitState::poll_stops() {
  while (true) {
    WaitStatus status;
    pid_t ret = do_wait(-1, true, WSTOPPED, 0, status);
    if (ret == 0) {
      return;
    }
    if (ret < 0) {
      if (errno == EINTR || errno == ECHILD) {
        return;
      }
      FATAL() << "Unexpected error polling for stops";
    }
    // We got a status for some task. Stash it.
    if (status.reaped()) {
      FATAL() << "Expected a stop!";
    }
    stop_statuses[ret].push_back(status);
  }
}

static WaitState& wait_state() {
  static WaitState static_state;
  return static_state;
}

WaitResult WaitManager::wait_stop(const WaitOptions& options) {
  return wait_state().wait(options, WSTOPPED);
}

WaitResult WaitManager::wait_exit(const WaitOptions& options) {
  if (options.unblock_on_other_tasks || !options.can_perform_syscall) {
    FATAL() << "We can't stash exit statuses";
  }
  if (!options.consume && (options.block_seconds > 0 || options.tid < 0)) {
    // We can't support this; a ptraced child that receives a signal will trigger
    // a ptrace stop that will be reported even by waitid(WEXITED). If we don't
    // consume the ptrace stop then we won't be able to wait for the exit.
    if (options.block_seconds > 0) {
      FATAL() << "Blocking non-consuming exit waits not supported";
    }
    FATAL() << "Non-consuming wait-for-any-process-exit not supported";
  }
  return wait_state().wait(options, WEXITED);
}

WaitResult WaitManager::wait_stop_or_exit(const WaitOptions& options) {
  if (options.unblock_on_other_tasks || !options.can_perform_syscall) {
    FATAL() << "We can't stash exit statuses";
  }
  return wait_state().wait(options, WSTOPPED | WEXITED);
}

void WaitManager::poll_stops() {
  wait_state().poll_stops();
}

} // namespace rr
