#ifndef REMOTE_H_
#define REMOTE_H_


void gdb_connect(int port);
char* get_command(struct rep_thread_context* context);

#endif /* REMOTE_H_ */
