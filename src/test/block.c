/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include "rrutil.h"

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static int sockfds[2];

static const int msg_magic = 0x1337beef;
const ssize_t num_sockbuf_bytes = 1 << 20;
/* TODO: rr doesn't know how to create scratch space for struct msghdr
 * yet, so it's forced to make the {send, recv}(m?)msg() functions
 * non-context-switchable.  This test would obviously deadlock in that
 * situation, so we help rr along by hiding the send->recv
 * synchronization behind a barrier, for now. */
static pthread_barrier_t cheater_barrier;

void* reader_thread(void* dontcare) {
	char token = '!';
	int sock = sockfds[1];
	struct timeval ts;
	char c = '\0';

	gettimeofday(&ts, NULL);

	atomic_puts("r: acquiring mutex ...");
	pthread_mutex_lock(&lock);
	atomic_puts("r:   ... releasing mutex");
	pthread_mutex_unlock(&lock);

	atomic_puts("r: reading socket ...");
	gettimeofday(&ts, NULL);
	test_assert(1 == read(sock, &c, sizeof(c)));
	atomic_printf("r:   ... read '%c'\n", c);
	test_assert(c == token);
	++token;

	atomic_puts("r: recv'ing socket ...");
	gettimeofday(&ts, NULL);
	test_assert(1 == recv(sock, &c, sizeof(c), 0));
	atomic_printf("r:   ... recv'd '%c'\n", c);
	test_assert(c == token);
	++token;
	{
		struct mmsghdr mmsg = {{ 0 }};
		struct iovec data = { 0 };
		int magic = ~msg_magic;

		data.iov_base = &magic;
		data.iov_len = sizeof(magic);
		mmsg.msg_hdr.msg_iov = &data;
		mmsg.msg_hdr.msg_iovlen = 1;

		atomic_puts("r: recmsg'ing socket ...");

		pthread_barrier_wait(&cheater_barrier);
		test_assert(0 < recvmsg(sock, &mmsg.msg_hdr, 0));
		atomic_printf("r:   ... recvmsg'd 0x%x\n", magic);
		test_assert(msg_magic == magic);

		magic = ~msg_magic;
		atomic_puts("r: recmmsg'ing socket ...");

		pthread_barrier_wait(&cheater_barrier);
		test_assert(1 == recvmmsg(sock, &mmsg, 1, 0, NULL));
		atomic_printf("r:   ... recvmmsg'd 0x%x (%u bytes)\n",
			      magic, mmsg.msg_len);
		test_assert(msg_magic == magic);
	}
	{
		struct pollfd pfd;

		atomic_puts("r: polling socket ...");
		pfd.fd = sock;
		pfd.events = POLLIN;
		gettimeofday(&ts, NULL);
		poll(&pfd, 1, -1);
		atomic_puts("r:   ... done, doing nonblocking read ...");
		test_assert(1 == read(sock, &c, sizeof(c)));
		atomic_printf("r:   ... read '%c'\n", c);
		test_assert(c == token);
		++token;
	}
	{
		struct pollfd pfd;

		atomic_puts("r: polling socket ...");
		pfd.fd = sock;
		pfd.events = POLLIN;
		gettimeofday(&ts, NULL);
		ppoll(&pfd, 1, NULL, NULL);
		atomic_puts("r:   ... done, doing nonblocking read ...");
		test_assert(1 == read(sock, &c, sizeof(c)));
		atomic_printf("r:   ... read '%c'\n", c);
		test_assert(c == token);
		++token;
	}
	{
		int epfd;
		struct epoll_event ev;

		atomic_puts("r: epolling socket ...");
		test_assert(0 <= (epfd = epoll_create(1/*num events*/)));
		ev.events = EPOLLIN;
		ev.data.fd = sock;
		gettimeofday(&ts, NULL);
		test_assert(0 == epoll_ctl(epfd, EPOLL_CTL_ADD, ev.data.fd,
					   &ev));
		test_assert(1 == epoll_wait(epfd, &ev, 1, -1));
		atomic_puts("r:   ... done, doing nonblocking read ...");
		test_assert(sock == ev.data.fd);
		test_assert(1 == read(sock, &c, sizeof(c)));
		atomic_printf("r:   ... read '%c'\n", c);
		test_assert(c == token);
		++token;

		close(epfd);
	}
	{
		char* buf = (char*)malloc(num_sockbuf_bytes);
		ssize_t nwritten = 0;

		++token;
		memset(buf, token, num_sockbuf_bytes);

		atomic_printf("r: writing outbuf of size %d ...\n",
			      num_sockbuf_bytes);
		while (nwritten < num_sockbuf_bytes) {
			ssize_t this_write =
				write(sock, buf,
				      num_sockbuf_bytes - nwritten);
			atomic_printf("r:   wrote %d bytes this time\n",
				      this_write);
			nwritten += this_write;
		}

		free(buf);
	}

	atomic_puts("r: reading socket with masked signals ...");
	{
		sigset_t old_mask, mask;
		sigfillset(&mask);
		test_assert(0 == pthread_sigmask(SIG_BLOCK, &mask, &old_mask));

		test_assert(1 == read(sock, &c, sizeof(c)));

		test_assert(0 == pthread_sigmask(SIG_SETMASK, &old_mask, NULL));
	}
	atomic_printf("r:   ... read '%c'\n", c);
	test_assert(c == token);
	++token;

	/* Make the main thread wait on our join() */
	atomic_puts("r: sleeping ...");
	usleep(500000);

	return NULL;
}

int main(int argc, char *argv[]) {
	char token = '!';
	struct timeval ts;
	pthread_t reader;
	int sock;

	gettimeofday(&ts, NULL);

	socketpair(AF_LOCAL, SOCK_STREAM, 0, sockfds);
	sock = sockfds[0];

	pthread_barrier_init(&cheater_barrier, NULL, 2);

	pthread_mutex_lock(&lock);

	pthread_create(&reader, NULL, reader_thread, NULL);

	/* Make the reader thread wait on its pthread_mutex_lock() */
	atomic_puts("M: sleeping ...");
	usleep(500000);
	atomic_puts("M: unlocking mutex ...");
	pthread_mutex_unlock(&lock);
	atomic_puts("M:   ... done");

	/* Force a wait on read() */
	atomic_puts("M: sleeping again ...");
	usleep(500000);
	atomic_printf("M: writing '%c' to socket ...\n", token);
	write(sock, &token, sizeof(token));
	++token;
	atomic_puts("M:   ... done");

	/* Force a wait on recv() */
	atomic_puts("M: sleeping again ...");
	usleep(500000);
	atomic_printf("M: sending '%c' to socket ...\n", token);
	send(sock, &token, sizeof(token), 0);
	++token;
	atomic_puts("M:   ... done");
	{
		struct mmsghdr mmsg = {{ 0 }};
		struct iovec data = { 0 };
		int magic = msg_magic;

		data.iov_base = &magic;
		data.iov_len = sizeof(magic);
		mmsg.msg_hdr.msg_iov = &data;
		mmsg.msg_hdr.msg_iovlen = 1;

		/* Force a wait on recvmsg() */
		atomic_puts("M: sleeping again ...");
		usleep(500000);
		atomic_printf("M: sendmsg'ing 0x%x to socket ...\n",
			      msg_magic);
		sendmsg(sock, &mmsg.msg_hdr, 0);
		atomic_puts("M:   ... done");
		pthread_barrier_wait(&cheater_barrier);

		/* Force a wait on recvmmsg() */
		atomic_puts("M: sleeping again ...");
		usleep(500000);
		atomic_printf("M: sendmmsg'ing 0x%x to socket ...\n",
			      msg_magic);
		sendmmsg(sock, &mmsg, 1, 0);
		atomic_printf("M:   ... sent %u bytes\n", mmsg.msg_len);
		pthread_barrier_wait(&cheater_barrier);
	}
	/* Force a wait on poll() */
	atomic_puts("M: sleeping again ...");
	usleep(500000);
	atomic_printf("M: writing '%c' to socket ...\n", token);
	write(sock, &token, sizeof(token));
	++token;
	atomic_puts("M:   ... done");

	/* Force a wait on ppoll() */
	atomic_puts("M: sleeping again ...");
	usleep(500000);
	atomic_printf("M: writing '%c' to socket ...\n", token);
	write(sock, &token, sizeof(token));
	++token;
	atomic_puts("M:   ... done");

	/* Force a wait on epoll_wait() */
	atomic_puts("M: sleeping again ...");
	usleep(500000);
	atomic_printf("M: writing '%c' to socket ...\n", token);
	write(sock, &token, sizeof(token));
	++token;
	atomic_puts("M:   ... done");

	/* Force a wait on write() */
	atomic_puts("M: sleeping again ...");
	usleep(500000);
	atomic_printf("M: reading socket ...\n");
	++token;
	{
		char* buf = (char*)malloc(num_sockbuf_bytes);
		ssize_t nread = 0;

		while (nread < num_sockbuf_bytes) {
			char* this_buf = buf + nread;
			ssize_t this_read = read(sock, this_buf,
						 num_sockbuf_bytes - nread);
			int i;

			atomic_printf("M:   read %d bytes this time,\n",
				      this_read);
			test_assert(this_read > 0);
			/* XXX: we would like to assert that the
			 * written data was read in more than one
			 * chunk, which should imply that at least one
			 * write() from the other thread blocked, but
			 * it's possible for multiple write()s to
			 * complete and fill the read buffer here
			 * before the reader returns. */
			/*test_assert(this_read < num_sockbuf_bytes);*/

			for (i = nread; i < nread + this_read; ++i) {
				if (token != buf[i]) {
					atomic_printf("M:   byte %d should be '%c', but is '%c'\n",
						      i, token, buf[i]);
				}
			}
			nread += this_read;
			atomic_printf("M:      %d total so far\n", nread);
		}

		free(buf);
	}
	atomic_puts("M:   ... done");

	/* Force a wait on read() */
	atomic_puts("M: sleeping again ...");
	usleep(500000);
	atomic_printf("M: writing '%c' to socket ...\n", token);
	write(sock, &token, sizeof(token));
	++token;
	atomic_puts("M:   ... done");

	pthread_join(reader, NULL);

	atomic_puts("EXIT-SUCCESS");
	return 0;
}
