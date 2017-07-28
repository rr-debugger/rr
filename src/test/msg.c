/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#define NUM_MSGS 3

struct msg {
  long mtype;
  long msg;
};

static void breakpoint(void) {
  int break_here = 1;
  (void)break_here;
}

static int msqid;

static void child(void) {
  const char* id = "c";
  int i;
  int ret;
  int err;
  struct msg msg;
  memset(&msg, 0, sizeof(msg));

  atomic_printf("%s: inherited msg id %d\n", id, msqid);
  test_assert(msqid >= 0);

  for (i = 1; i < NUM_MSGS; ++i) {
    atomic_printf("%s: msgrcv() ...\n", id);
    ret = msgrcv(msqid, &msg, sizeof(msg.msg), i, 0);
    err = errno;
    atomic_printf("%s: ... returned %d (%s/%d): (%ld, %ld)\n", id, ret,
                  strerror(err), err, msg.mtype, msg.msg);
    test_assert(sizeof(msg.msg) == ret);
    test_assert(msg.mtype + 1 == msg.msg);
  }

  atomic_printf("%s: awaiting Q destruction ...\n", id);
  ret = msgrcv(msqid, &msg, sizeof(msg.msg), i, 0);
  err = errno;
  atomic_printf("%s: ... returned %d (%s/%d)\n", id, ret, strerror(err), err);
  test_assert(-1 == ret && EIDRM == err);
  atomic_printf("%s: ... done\n", id);

  exit(0);
}

int main(void) {
  const char* id = "P";
  int ret;
  int err;
  pid_t c;
  struct msqid_ds buf;
  struct msginfo info;
  int i;
  int status;
  struct msg msg;
  memset(&msg, 0, sizeof(msg));

  breakpoint();
  /* NB: no syscalls between here and |msgget()| below. */

  /* NB: surprisingly, this test will leak Q's on failure, even
   * though we're using IPC_PRIVATE.  There doesn't appear to be
   * a way to avoid that. */
  msqid = msgget(IPC_PRIVATE, 0600);
  atomic_printf("%s: got id %d for key %d\n", id, msqid, IPC_PRIVATE);
  test_assert(msqid >= 0);

  memset(&buf, 0x5a, sizeof(buf));
  test_assert(0 == msgctl(msqid, IPC_STAT, &buf));
  atomic_printf("%s: Q stats in %p:\n"
                "    { perm:%#o qnum:%ld lspid:%d lrpid:%d }\n",
                id, &buf, buf.msg_perm.mode, buf.msg_qnum, buf.msg_lspid,
                buf.msg_lrpid);

  memset(&info, 0x5a, sizeof(info));
  ret = msgctl(msqid, IPC_INFO, (struct msqid_ds*)&info);
  err = errno;
  atomic_printf("%s: IPC_INFO returned %d (%s/%d):\n"
                "    { max:%d mnb:%d mni:%d }\n",
                id, ret, strerror(err), err, info.msgmax, info.msgmnb,
                info.msgmni);
  test_assert(ret >= 0);

  memset(&info, 0x5a, sizeof(info));
  ret = msgctl(msqid, MSG_INFO, (struct msqid_ds*)&info);
  err = errno;
  atomic_printf("%s: MSG_INFO returned %d (%s/%d):\n"
                "    { pool:%d map:%d tql:%d }\n",
                id, ret, strerror(err), err, info.msgpool, info.msgmap,
                info.msgtql);
  test_assert(ret >= 0);

  if ((0 == (c = fork()))) {
    child();
    test_assert("Not reached" && 0);
  }

  /* Make the child wait on msgrcv() a few times. */
  for (i = 1; i < NUM_MSGS; ++i) {
    atomic_printf("%s: sleeping ...\n", id);
    usleep(500000);

    msg.mtype = i;
    msg.msg = msg.mtype + 1;
    atomic_printf("%s: sending msg (%ld, %ld) ...\n", id, msg.mtype, msg.msg);
    ret = msgsnd(msqid, &msg, sizeof(msg.msg), 0);
    err = errno;
    atomic_printf("%s: ... returned %d (%s/%d)\n", id, ret, strerror(err), err);
    test_assert(0 == ret);
    atomic_printf("%s:   ... done\n", id);
  }

  memset(&buf, 0x5a, sizeof(buf));
  test_assert(0 == msgctl(msqid, IPC_STAT, &buf));
  atomic_printf("%s: Q stats: { perm:%#o qnum:%ld lspid:%d lrpid:%d }\n", id,
                buf.msg_perm.mode, buf.msg_qnum, buf.msg_lspid, buf.msg_lrpid);

  /* Make the child wait on msgrcv() returning EIDRM. */
  atomic_printf("%s: sleeping ...\n", id);
  usleep(500000);
  atomic_printf("%s: destroying msg Q ...\n", id);
  test_assert(0 == msgctl(msqid, IPC_RMID, NULL));
  atomic_printf("%s:   ... done", id);

  atomic_printf("%s: joining %d ...\n", id, c);
  ret = waitpid(c, &status, 0);
  atomic_printf("%s: ... joined %d with status %#x\n", id, ret, status);
  test_assert(c == ret && WIFEXITED(status) && 0 == WEXITSTATUS(status));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
