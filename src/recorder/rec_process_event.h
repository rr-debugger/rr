#ifndef PROCESS_SYSCALL_H_
#define PROCESS_SYSCALL_H_

#include "../share/types.h"

void rec_process_syscall(struct context *ctx, struct flags rr_flags);
void process_thread_start(pid_t pid);

/*
 * Macros to make the recording of syscalls easier. The suffix
 * denotes the number of buffers that have to be recorded, which
 * can usually be inferred from the syscall function signature.
 */

#define SYS_REC0(syscall) \
	case SYS_##syscall: { \
	break; }


#define SYS_REC1(syscall_,size,addr) \
	case SYS_##syscall_: { \
		record_child_data(ctx, syscall, size, addr); \
	break; }


#define SYS_REC1_STR(syscall_,addr) \
	case SYS_##syscall_: { \
		record_child_str(tid, syscall, addr); \
	break; }


#define SYS_REC2(syscall_,size1,addr1,size2,addr2) \
	case SYS_##syscall_: { \
		record_child_data(ctx, syscall, size1, addr1);\
		record_child_data(ctx, syscall, size2, addr2); \
	break; }

#define SYS_REC3(syscall_,size1,addr1,size2,addr2,size3,addr3) \
	case SYS_##syscall_: { \
		record_child_data(ctx, syscall, size1, addr1);\
		record_child_data(ctx, syscall, size2, addr2);\
		record_child_data(ctx, syscall, size3, addr3);\
	break; }

#define SYS_REC4(syscall_,size1,addr1,size2,addr2,size3,addr3,size4,addr4) \
	case SYS_##syscall_: { \
		record_child_data(ctx, syscall, size1, addr1);\
		record_child_data(ctx, syscall, size2, addr2);\
		record_child_data(ctx, syscall, size3, addr3);\
		record_child_data(ctx, syscall, size4, addr4);\
		break; }



#endif /* PROCESS_SYSCALL_H_ */
