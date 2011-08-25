#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>

#include "replayer.h"

#include "../share/ipc.h"
#include "../share/types.h"
#include "../share/sys.h"

#define NUM_REGS		16
#define BUFFER_SIZE 	1024
#define MAX_TRACE_VAR	128

static int __fd;
static char buf[BUFFER_SIZE];
static char hexchars[] = "0123456789abcdef";

enum regs
{
	eax, ecx, edx, ebx, esp, ebp, esi, edi, eip, eflags, xcs, xss, xds, xes, xfs, xgs
};

void put_char(char c)
{
	if (write(__fd, &c, 1) != 1) {
		perror("error writing to client\n");
	}
}

char get_char()
{
	char c;

	if (read(__fd, &c, 1) < 0) {
		perror("error reading from client\n");
	}
	return c;
}

void send_msg(char* msg)
{
	printf("sending message: %s\n", msg);

	int i = 0;
	unsigned char byte, checksum = 0;

	put_char('$');

	while ((byte = msg[i]) != 0) {
		put_char(byte);
		checksum += byte;
		i++;
	}

	put_char('#');
	put_char(hexchars[(checksum >> 4) & 0xf]);
	put_char(hexchars[checksum & 0xf]);
}

void get_msg(char* buf, int max_size)
{
	unsigned char tmp;
	unsigned char c_sum[3];
	int checksum_calc = 0, idx = 0, checksum_rcv;

	/* reset the buffer */
	bzero(buf, BUFFER_SIZE);

	/* start reading at the start symbol */
	while ((tmp = get_char()) != '$') {
	}

	/* put the message in the buffer */
	while ((tmp = get_char()) != '#') {
		buf[idx] = tmp;
		checksum_calc += tmp;
		idx++;
		assert(idx < max_size);
	}
	buf[idx] = tmp;

	printf("received message: %s\n", buf);
	checksum_calc %= 256;
	c_sum[0] = get_char();
	c_sum[1] = get_char();
	c_sum[2] = '\0';

	checksum_rcv = strtol(c_sum, NULL, 16);

	/* wrong checksum; request retransmission */
	if (checksum_calc != checksum_rcv) {
		printf("calc: %d  rcv: %d\n", checksum_calc, checksum_rcv);
		put_char('-');
		assert(1==0);
	} else {
		put_char('+');
	}
}

void return_to_prog()
{

}

void gdb_connect(int port)
{

	int sockfd;
	socklen_t clilen;
	struct sockaddr_in serv_addr, cli_addr;

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		perror("ERROR opening socket");
	}

	bzero((char *) &serv_addr, sizeof(serv_addr));

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(port);
	if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
		if (sockfd > 0) {
			close(sockfd);
		}
		perror("ERROR on binding");
		exit(0);
	}

	if (listen(sockfd, 5) < 0) {
		perror("ERROR on accept");
	}

	clilen = sizeof(cli_addr);

	if ((__fd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen)) < 0) {
		perror("ERROR on accept");
	}
	printf("got soscket: %d\n", __fd);
}

void gdb_disconnect()
{
	if (__fd > 0) {
		close(__fd);
	}
}

static int hexstr_to_li(const char* str, char limiter, long int* ret_val)
{
	int idx = 0;
	char tmp[2];

	tmp[1] = '\0';
	long int val = 0;

	while ((tmp[0] = str[idx]) != limiter) {
		assert(strtol(tmp, (char **) NULL, 16) < 16);
		val <<= 4;
		val += strtol(tmp, (char **) NULL, 16);
		idx++;
	}

	*ret_val = val;
	return ++idx;
}

static void int_to_hex_8_little_endian(char* buf, int val)
{
	int i;
	char tmp[9];

	sprintf(tmp, "%8x", val);
	for (i = 0; i < 8; i++) {
		buf[i] = (tmp[i] == ' ') ? '0' : tmp[i];
	}
}

static void int_to_hex_8_big_endian(char* buf, int val)
{
	int i, j;
	char tmp[9];

	sprintf(tmp, "%8x", val);
	for (i = 7, j = 0; i >= 0; i -= 2, j += 2) {
		buf[j] = (tmp[i - 1] == ' ') ? '0' : tmp[i - 1];
		buf[j + 1] = (tmp[i] == ' ') ? '0' : tmp[i];
	}
}

#define DUMP_REG(reg,regs,ptr) \
		int_to_hex_8_big_endian(ptr,regs.reg);\
		ptr += 8;

static void dump_regsiter(pid_t tid, char* buf, int reg_id)
{
	struct user_regs_struct regs;
	char* ptr = buf;

	read_child_registers(tid, &regs);

	switch (reg_id) {
	case 8:
	DUMP_REG(eip,regs,ptr)
	;
		break;

	default:
	printf("undefined reg_id: %d\n", reg_id);
	}
}

static void dump_registers(pid_t tid, char* buf)
{
	struct user_regs_struct regs;
	char* ptr = buf;

	read_child_registers(tid, &regs);

	DUMP_REG(eax,regs,ptr)
	DUMP_REG(ecx,regs,ptr)
	DUMP_REG(edx,regs,ptr)
	DUMP_REG(ebx,regs,ptr)
	DUMP_REG(esp,regs,ptr)
	DUMP_REG(ebp,regs,ptr)
	DUMP_REG(esi,regs,ptr)
	DUMP_REG(edi,regs,ptr)
	DUMP_REG(eip,regs,ptr)
	DUMP_REG(eflags,regs,ptr)
	DUMP_REG(xcs,regs,ptr)
	DUMP_REG(xds,regs,ptr)
	DUMP_REG(xes,regs,ptr)
	DUMP_REG(xfs,regs,ptr)
	DUMP_REG(xgs,regs,ptr)
	*ptr = '\0';
}

static int to_hex(const char* src, char* dest, int size)
{

	int i, j, count = 0;
	char tmp;

	for (i = 0, j = 0; i < size; i++, j += 2) {
		tmp = src[i];
		dest[j] = hexchars[tmp & 0xf];
		dest[j + 1] = hexchars[(tmp >> 4) & 0xf];
		count++;
	}
	return ++count;
}

static void process_memory(pid_t tid, char* cmd)
{
	int byte_count;
	long int addr = 0, size = 0;
	char* ret, *tmp;

	byte_count = hexstr_to_li(cmd, ',', &addr);
	cmd += byte_count;
	hexstr_to_li(cmd, '#', &size);

	ret = (char*) read_child_data_tid(tid, size, addr);
	tmp = (char*) sys_malloc(2 * size + 1);
	to_hex(ret, tmp, size);
	tmp[2 * size] = '\0';
	send_msg(tmp);
	sys_free((void**) &ret);
	sys_free((void**) &tmp);
}

static void process_stop_reply(char* cmd)
{
	send_msg("T05");
}

static int process_thread_operation(char* cmd)
{
	if (cmd[0] == 'g') {
		send_msg("OK");
	} else if (cmd[0] == 'c') {
		send_msg("OK");
	} else {
		printf("unsupported: %s\n", cmd);
		assert(1==0);
	}

	return 0;
}

static void process_query(struct context* context, char* cmd)
{
	printf("length: %d\n", strlen(cmd));

	/* return the current thread id */
	if (strncmp(cmd, "C", 1) == 0) {
		char buf[9];
		bzero(buf, 9);
		int_to_hex_8_little_endian(buf, context->child_tid);
		send_msg(buf);
		/*
		 * These packets request data about trace state variables that are on the target.
		 * gdb sends qTfV to get the first vari of data, and multiple qTsV to get additional
		 * variables. Replies to these packets follow the syntax of the QTDV packets that
		 * define trace state variables
		 */
	} else if (strncmp(cmd, "TfV", 3) == 0) {
		/* QTDV:n:value */
		//char buf[64];
		//bzero(buf,64);
		//sprintf(buf,"QTDV:%x:%llx",trace_val_count,trace_var[trace_val_count]);
		//send_msg(buf);
		send_msg("");
		/* see TfV */
	} else if (strncmp(cmd, "TfP", 3) == 0) {
		send_msg("");
	} else if (strncmp(cmd, "Offset", 6) == 0) {
		send_msg("");
	} else if (strncmp(cmd, "Symbol", 6) == 0) {
		send_msg("OK");
	} else if (strncmp(cmd, "TStatus", 7) == 0) {
		send_msg("T0");
	} else if (strncmp(cmd, "Attached", 8) == 0) {
		send_msg("0");
	} else if (strncmp(cmd, "Supported", 9) == 0) {

		/* send not supported */
		send_msg("");
	} else if (strncmp(cmd, "RelocInsn", 9) == 0) {
		/* and checks here */

		/* send response */
		//not quite sure yet what to reposnse here
	} else {
		printf("unsupported: %s\n", cmd);
		assert(1==0);
	}
}

static void process_breakpoint(pid_t tid, char* cmd)
{
	int byte_count;
	long int addr, type;

	if (cmd[0] == '0') {
		/*cmd += 2;
		byte_count = hexstr_to_li(cmd + 2, ',', &addr);
		cmd += byte_count;
		hexstr_to_li(cmd, '#', &type);*/

		//TODO: insert code for breakpoint here
		send_msg("OK");
	} else {
		assert(1==0);
	}
}


static int internal_command(struct context* context, char* command)
{
	int start_idx = 0, end_idx = 0;
	int last_cmd = 0;
	char current_cmd[128];

	while (1) {
		bzero(current_cmd, 128);
		/* read the current command */
		start_idx = end_idx;
		while (command[end_idx] != ';' && command[end_idx] != '#') {
			end_idx++;
		}

		if (command[end_idx] == '#') {
			last_cmd = 1;
		}

		end_idx++;

		assert (end_idx - start_idx < 128);
		strncpy(current_cmd, command + start_idx, (end_idx - start_idx));
		printf("current cmd: %s\n", current_cmd);

		/* main parsing of command */
		switch (current_cmd[0]) {

		case 'q':
		{
			process_query(context, current_cmd + 1);
			break;
		}

		case 'H':
		{
			if (process_thread_operation(current_cmd + 1)) {
				assert(last_cmd == 1);
				return 1;
			}
			break;
		}

		case '?':
		{
			process_stop_reply(current_cmd);
			break;
		}

		case 'g':
		{
			char buf[256];
			dump_registers(context->child_tid, buf);
			send_msg(buf);
			break;
		}

		case 'p':
		{
			char buf[9];
			long int reg_id;

			hexstr_to_li(current_cmd + 1, '\0', &reg_id);
			bzero(buf, 9);
			dump_regsiter(context->child_tid, buf, reg_id);
			send_msg(buf);
			break;
		}

		case 'm':
		{
			printf("m-command: %s\n", current_cmd);
			process_memory(context->child_tid, current_cmd + 1);
			break;
		}

		case 'k':
		{
			return -1;
			break;
		}

		case 'Z':
		{
			process_breakpoint(context->child_tid, current_cmd + 1);
			break;
		}

		case 'v':
		{
			send_msg("");
			break;
		}

		case 'c':
		{
			if (current_cmd[1] == '#') {
				return 1;
			}
			assert(1==0);
			break;
		}

		default:
		printf("command not supported: %s\n", command);
		assert(1==0);
		}

		if (last_cmd) {
			break;
		}
	}

	printf("ending up here\n");
	return 0;
}


char* get_command(struct rep_thread_context* context)
{
	printf("getting new message?\n"); fflush(stdout);
	int internal = 0;
	while (!internal) {
		get_msg(buf, 127);
		printf("got message: %s\n", buf);
		internal = internal_command(context, buf);
	}

	return buf;
}
