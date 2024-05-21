#ifndef __SECCOMP
#define __SECCOMP

#define MAX_FILENAME_LEN 127
#define TASK_COMM_LEN 16
#define MAX_LINE_SIZE 80
typedef int pid_t;

struct containerd_rootfs {
	char rootfs[120];
	int number;
};
struct shim_process {
	int pid;//shim2
	int ppid;//shim1
};
struct container_process {
	int pid;
	int ppid;//parent id
    char cid[64];//docker id
	/*char comm[TASK_COMM_LEN];
	char filename[MAX_FILENAME_LEN];*/
};
#endif