#ifndef __PHASE
#define __PHASE

#define MAX_FILENAME_LEN 127
#define TASK_COMM_LEN 16
#define MAX_LINE_SIZE 80

#ifndef CONTAINER_STAGE
#define CONTAINER_STAGE
#define START 0x01
#define INIT 0x02
#define FIFO 0x04
// #define RUNC_INIT 0x08
// #define RUNC_CONTAINER_INIT 0x10
// #define READ_FIFOFD 0x20
#endif // !CONTAINER_STAGE

#define DIS_MODE
#define SYS_ID 0
#define SYS_NAME 1

#define TASK_COMM_LEN	 16
#define MAX_FILENAME_LEN 127
#define CONTAINER_ID_LEN 127
#define SYSCALL_TASK_COMM_LEN 64

typedef int pid_t;


struct syscall_event
{
        int pid;
        int ppid;
        uint32_t syscall_id;
        uint64_t mntns;
        char comm[SYSCALL_TASK_COMM_LEN];
        unsigned char occur_times;
        int con_id;
	int state;
};


#endif