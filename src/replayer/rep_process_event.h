#ifndef REP_PROCESS_EVENT_H_
#define REP_PROCESS_EVENT_H_

#include "../share/types.h"
#include "../share/trace.h"

void rep_process_syscall(struct context* context);


#define EMU_FD			1

/*********************** All system calls that are emulated are handled here *****************************/


#define SYS_EMU_ARG(syscall,num) \
	case SYS_##syscall: { \
		if (state == STATE_SYSCALL_ENTRY) { goto_next_syscall_emu(context);}\
		else {\
			int i; for (i=0;i<(num);i++) {set_child_data(context);}\
			set_return_value(context); \
			validate_args(context); \
			finish_syscall_emu(context);} \
	break; }





#define SYS_EXEC_ARG(syscall,num) \
	case SYS_##syscall: { \
		if (state == STATE_SYSCALL_ENTRY) { __ptrace_cont(context);}\
		else {\
			__ptrace_cont(context);\
			int i; for (i = 0; i < num; i++) {set_child_data(context);}\
			set_return_value(context); \
			validate_args(context);}\
	break; }


#define SYS_EXEC_ARG_RET(ctx,syscall,num) \
	case SYS_##syscall: { \
		if (state == STATE_SYSCALL_ENTRY) { __ptrace_cont(ctx);}\
		else {\
			__ptrace_cont(ctx);\
			int i; for (i = 0; i < num; i++) {set_child_data(ctx);}\
			validate_args(ctx);}\
	break; }




/*********************** All system calls that include file descriptors are handled here *****************************/
#ifdef EMU_FD

#define SYS_FD_ARG(syscall,num) \
	SYS_EMU_ARG(syscall,num)
#define SYS_FD_USER_DEF(syscall,fixes,code) \
	case SYS_##syscall: { \
		if (state == STATE_SYSCALL_ENTRY) {goto_next_syscall_emu(context);}\
		else {code \
			validate_args(context);\
			finish_syscall_emu(context);}\
	break; }



#else /* all operations on fd are executed */

#define SYS_FD_ARG0(syscall)\
	case SYS_##syscall: { \
		if (state == STATE_SYSCALL_ENTRY) {ptrace_cont(context);}\
		else {ptrace_cont(context); \
		validate_args(context);} \
	break; }
#define SYS_FD_REG_ARG1(syscall, reg) \
	case SYS_##syscall: { \
		if (state == STATE_SYSCALL_ENTRY) {ptrace_cont(context);}\
		else {ptrace_cont(context); \
		fix_raw_data_ptr(context);\
		validate_args(context);} \
	break; }
#define SYS_FD_ADR_ARG2(syscall, addr1, addr2) \
	case SYS_##syscall: { \
		if (state == STATE_SYSCALL_ENTRY) {ptrace_cont(context, trace);}\
		else {ptrace_cont(context); \
		fix_raw_data_ptr(context);\
		fix_raw_data_ptr(context);\
		validate_args(context);} \
	break; }

#define SYS_FD_USER_DEF(syscall,fixes,code) \
	case SYS_##syscall: { \
		if (state == STATE_SYSCALL_ENTRY) {ptrace_cont(context);}\
		else {ptrace_cont(context); \
		int i__;for(i__=0;i__<fixes;i__++) {\
		fix_raw_data_ptr(context);}\
		validate_args(context);} \
	break; }

#endif











#endif /* REP_PROCESS_EVENT_H_ */
