/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {

  mqd_t mq_a;
  mqd_t mq_b;
  struct mq_attr mq_attr;
  struct mq_attr mq_attr_test;
  char msg[] = "Hello";
  char buffer[1024] = { 0 }; /* 'C' fills in the rest of the array with 0s. */
  unsigned prio;
  struct timespec expiry;

  mq_attr.mq_flags = 0;
  mq_attr.mq_maxmsg = 10;
  mq_attr.mq_msgsize = 1024;
  mq_attr.mq_curmsgs = 0;
  char mq_name[100];
  snprintf(mq_name, 100, "/rr-test-queue%d", sys_gettid());
  mq_a = mq_open(mq_name, O_WRONLY | O_CREAT, 0777, &mq_attr);
  test_assert(mq_a != -1);

  mq_b = mq_open(mq_name, O_RDONLY);
  test_assert(mq_b != -1);

  test_assert(mq_getattr(mq_a, &mq_attr_test) == 0);
  test_assert(mq_attr_test.mq_flags == mq_attr.mq_flags);
  test_assert(mq_attr_test.mq_maxmsg == mq_attr.mq_maxmsg);
  test_assert(mq_attr_test.mq_msgsize == mq_attr.mq_msgsize);
  test_assert(mq_attr_test.mq_curmsgs == 0);

  test_assert(mq_getattr(mq_b, &mq_attr_test) == 0);
  test_assert(mq_attr_test.mq_flags == mq_attr.mq_flags);
  test_assert(mq_attr_test.mq_maxmsg == mq_attr.mq_maxmsg);
  test_assert(mq_attr_test.mq_msgsize == mq_attr.mq_msgsize);
  test_assert(mq_attr_test.mq_curmsgs == 0);

  test_assert(sizeof(msg) == 6);
  test_assert(mq_send(mq_a, msg, sizeof(msg), 100) == 0);
  test_assert(mq_getattr(mq_b, &mq_attr_test) == 0);
  test_assert(mq_attr_test.mq_curmsgs == 1);

  prio = ~0;
  test_assert(mq_receive(mq_b, buffer, sizeof(buffer), &prio) == sizeof(msg));
  test_assert(memcmp(msg, buffer, sizeof(msg)) == 0);
  test_assert(prio == 100);

  clock_gettime(CLOCK_REALTIME, &expiry);
  expiry.tv_sec += 2;
  test_assert(mq_timedreceive(mq_b, buffer, sizeof(buffer), &prio, &expiry) ==
              -1);

  mq_unlink(mq_name);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
