/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include "rrutil.h"

#define MAGIC 0x1cd00d00

static void child(int sock, int fd_minus_one) {
	struct sockaddr addr;
	int fd;
	struct msghdr msg = { 0 };
	union {
		int ints[2];
		byte bytes[sizeof(int[2])];
	} mbuf;
	struct iovec iov;
	byte cbuf[CMSG_SPACE(sizeof(fd))];
	const struct cmsghdr* cmsg;
	int zero = ~0;
	ssize_t nread;

	memset(&addr, 0x51, sizeof(addr));
	msg.msg_name = &addr;
	msg.msg_namelen = sizeof(addr);

	mbuf.ints[0] = mbuf.ints[1] = ~MAGIC;
	iov.iov_base = mbuf.bytes;
	iov.iov_len = sizeof(mbuf);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cbuf;
	msg.msg_controllen = sizeof(cbuf);
	msg.msg_flags = -1;

	atomic_printf("c: receiving msg ...\n");
	nread = recvmsg(sock, &msg, 0);

	atomic_printf("c:   ... got %#x (%d bytes), %d control bytes\n",
		      mbuf.ints[0], nread, msg.msg_controllen);
	test_assert(nread == sizeof(mbuf.ints[0]));
	test_assert(MAGIC == mbuf.ints[0]);
	test_assert(~MAGIC == mbuf.ints[1]);
	test_assert(msg.msg_controllen == sizeof(cbuf));

	atomic_printf("c:   ... and %d name bytes\n", msg.msg_namelen);
	test_assert(0 == msg.msg_namelen);

	atomic_printf("c:  ... and flags %d\n", msg.msg_flags);
	test_assert(0 == msg.msg_flags);

	cmsg = CMSG_FIRSTHDR(&msg);
	test_assert(SOL_SOCKET == cmsg->cmsg_level
		    && SCM_RIGHTS == cmsg->cmsg_type);
	fd = *(int*)CMSG_DATA(cmsg);
	atomic_printf("c:   ... and fd %d; should have received %d\n",
		      fd, fd_minus_one + 1);
	test_assert(fd - 1 == fd_minus_one || fd - 2 == fd_minus_one);

	atomic_printf("c: reading from /dev/zero ...\n");
	nread = read(fd, &zero, sizeof(zero));
	atomic_printf("c:   ... got %d (%d bytes) %s\n", zero, nread, strerror(errno));
	test_assert(0 == zero);

	exit(0);
}

int main(int argc, char *argv[]) {
	int sockfds[2];
	int sock;
	pid_t c;
	int fd;
	struct msghdr msg = { 0 };
	int mbuf = MAGIC;
	struct iovec iov;
	byte cbuf[CMSG_SPACE(sizeof(fd))];
	struct cmsghdr* cmsg;
	ssize_t nsent;
	int err;
	int status;

	test_assert(0 == socketpair(AF_LOCAL, SOCK_STREAM, 0, sockfds));
	sock = sockfds[0];

	fd = open("/dev/null", O_WRONLY);

	if (0 == (c = fork())) {
		child(sockfds[1], fd);
		test_assert("Not reached" && 0);
	}

	usleep(500000);
	fd = open("/dev/zero", O_RDONLY);

	iov.iov_base = &mbuf;
	iov.iov_len = sizeof(mbuf);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	msg.msg_control = cbuf;
	msg.msg_controllen = sizeof(cbuf);
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(fd));
	*(int*)CMSG_DATA(cmsg) = fd;

	atomic_printf("P: sending %#x with fd %d ...\n", mbuf, fd);
	nsent = sendmsg(sock, &msg, 0);
	err = errno;
	atomic_printf("P:   ... sent %d bytes (%s/%d)\n", nsent,
		      strerror(err), err);
	test_assert(0 < nsent);

	atomic_printf("P: waiting on child %d ...\n", c);
	test_assert(c == waitpid(c, &status, 0));
	test_assert(WIFEXITED(status) && 0 == WEXITSTATUS(status));

	atomic_puts("EXIT-SUCCESS");
	return 0;
}
