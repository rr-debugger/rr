/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include "rrutil.h"


static void client(const struct sockaddr_un* addr) {
	int clientfd;

	clientfd = socket(AF_UNIX, SOCK_STREAM, 0);
	test_assert(0 == connect(clientfd, (struct sockaddr*)addr,
				 sizeof(*addr)));
}

static void server() {
	struct sockaddr_un addr;
	int listenfd;
	int servefd;
	struct sockaddr_un peer_addr;
	socklen_t len = sizeof(peer_addr);;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, "socket.unix", sizeof(addr.sun_path) - 1);
	
	test_assert(0 <= (listenfd = socket(AF_UNIX, SOCK_STREAM, 0)));
	test_assert(0 == bind(listenfd, (struct sockaddr*)&addr,
			      sizeof(addr)));
	test_assert(0 == listen(listenfd, 1));

	if (0 == fork()) {
		return client(&addr);
	}

	test_assert(0 <= (servefd = accept(listenfd,
					   (struct sockaddr*)&peer_addr,
					   &len)));
	test_assert(AF_UNIX == peer_addr.sun_family);

	unlink(addr.sun_path);

	atomic_puts("EXIT-SUCCESS");
}

int main(int argc, char *argv[]) {
	server();
	return 0;
}
