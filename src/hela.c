#include "config.h"
#include "hela.h"

#include <string.h>

int volatile exiting = 0;
char name[50] = "nothing";

static void sig_handler(int sig)
{
	exiting = 1;
}

int container_syscall_tracing(char *output_path, int mode)
{
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	if (NONE == mode) {
		/* Print table title */
		printf("name : %s\n", name);
		printf("%s      %-8s      %-16s\n", "CONTAINER", "PID", "SYSCALL_ID");
        	return start_trackers_without_division(output_path, exiting, name);
	} else if (PHASE_DIV == mode) {
		/* Print table title */
		printf("%s      %-8s      %-16s     %-24s\n", "TIME", "PID", "SYSCALL_ID", "PHASE");
		system("../ebpf/container/phase");
		// return start_trackers_with_division(output_path, exiting);
	}

	
        
}

// TODO:解析命令行参数
int parse_args(int argc, char *argv[])
{
	int opt;
	int ret = NONE;
	while ((opt = getopt(argc, argv, "m:n:")) != -1) {
		switch (opt)
		{
			case 'm':
				if (strcmp(optarg, "phase") == 0) {
					ret = PHASE_DIV;
					break;
				} else if (strcmp(optarg, "none") == 0) {
					ret = NONE;
					break;
				}
			case 'n':
				int name_size = strlen(optarg);
				if (name_size > 50) {
					name_size = 50;
				}
				memset(name, 0, sizeof(name));
				strncpy(name, optarg, name_size);
				printf("name is : %s\n", name);
				break;
		default:
			ret = NONE;
			break;
		}
	}
	return ret;
}

int main(int argc, char **argv)
{
	// TODO:
        int ret;

        /* Init */

	/* parse */
	int mode = parse_args(argc, argv);

        /* Tracing */
        container_syscall_tracing(NULL, mode);
	ret = 0;
	return ret;
}