#ifndef __PHASE
#define __PHASE

#define MAX_FILENAME_LEN 127
#define TASK_COMM_LEN 16
#define MAX_LINE_SIZE 80

#ifndef CONTAINER_STAGE
#define CONTAINER_STAGE
#define CREATE 0x01
#define CONFIG 0x02
#define BOOT 0x04
#define RUNC_INIT 0x08
#define RUNC_CONTAINER_INIT 0x10
#define READ_FIFOFD 0x20
#endif // !CONTAINER_STAGE



#define TASK_COMM_LEN	 16
#define MAX_FILENAME_LEN 127
#define CONTAINER_ID_LEN 127

#include "../process/process.h"


typedef int pid_t;


struct container_process {
	int pid;
	int ppid;//parent id
        char cid[20]; // docker id
	int stage; // process stage
        
	/*char comm[TASK_COMM_LEN];
	char filename[MAX_FILENAME_LEN];*/
	struct process_event *pe;
}; 


#endif