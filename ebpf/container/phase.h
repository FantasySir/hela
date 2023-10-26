#ifndef __PHASE
#define __PHASE

#define MAX_FILENAME_LEN 127
#define TASK_COMM_LEN 16
#define MAX_LINE_SIZE 80
typedef int pid_t;


struct container_process {
	int pid;
	int ppid;//parent id
    char cid[20];//docker id
	/*char comm[TASK_COMM_LEN];
	char filename[MAX_FILENAME_LEN];*/
};
#endif