/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include "rrutil.h"

int main(int argc, char *argv[]) {
	int ret;
	struct winsize w;

	memset(&w, 0x5a, sizeof(w));
	ret = ioctl(STDIN_FILENO, TIOCGWINSZ, &w);
	atomic_printf("TIOCWINSZ returned {row:%d col:%d} (ret:%d)\n",
		      w.ws_row, w.ws_col, ret);

	atomic_puts("EXIT-SUCCESS");
	return 0;
}
