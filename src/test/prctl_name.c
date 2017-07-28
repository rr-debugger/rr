/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* Max name length is 16 bytes, *without* null terminator. */
#define PRNAME_NUM_BYTES 16

const char* exe_image;

const char main_name[] = "main";
const char thread_name[] = "thread";
const char fork_child_name[] = "fchild";
const char exec_child_name[] = "echild";

static void assert_prname_is(const char* tag, const char* name) {
  char prname[PRNAME_NUM_BYTES] = "";
  test_assert(0 == prctl(PR_GET_NAME, prname));

  atomic_printf("%s: prname is '%s'; expecting '%s'\n", tag, prname, name);
  test_assert(!strcmp(prname, name));
}

static void* thread(__attribute__((unused)) void* unused) {
  pid_t child;

  assert_prname_is("thread", main_name);

  prctl(PR_SET_NAME, thread_name);
  assert_prname_is("thread", thread_name);

  if ((child = fork())) {
    int status;

    test_assert(child == waitpid(child, &status, 0));
    test_assert(WIFEXITED(status) && 0 == WEXITSTATUS(status));

    assert_prname_is("thread", thread_name);

    return NULL;
  }

  assert_prname_is("fork child", thread_name);

  prctl(PR_SET_NAME, fork_child_name);
  assert_prname_is("fork child", fork_child_name);

  execl(exe_image, exe_image, "exec child", NULL);
  test_assert("Not reached" && 0);

  return NULL;
}

char initial_name[PRNAME_NUM_BYTES] = "";
static void compute_initial_name(const char* exe_image) {
  const char* basename = strrchr(exe_image, '/');
  if (basename) {
    /* Eat the '/' character. */
    ++basename;
  } else {
    /* Image path is already a basename. */
    basename = exe_image;
  }

  atomic_printf("  (basename of exe path '%s' is '%s')\n", exe_image, basename);

  strncpy(initial_name, basename, sizeof(initial_name) - 1);
}

int main(int argc, char* argv[]) {
  pthread_t t;

  exe_image = argv[0];
  compute_initial_name(exe_image);

  if (2 == argc) {
    assert_prname_is("exec child", initial_name);

    prctl(PR_SET_NAME, exec_child_name);
    assert_prname_is("exec child", exec_child_name);
    return 0;
  }

  assert_prname_is("main", initial_name);

  test_assert(-1 == prctl(PR_SET_NAME, NULL));
  test_assert(EFAULT == errno);
  assert_prname_is("main", initial_name);

  prctl(PR_SET_NAME, main_name);
  assert_prname_is("main", main_name);

  test_assert(0 == pthread_create(&t, NULL, thread, NULL));
  pthread_join(t, NULL);

  assert_prname_is("main", main_name);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
