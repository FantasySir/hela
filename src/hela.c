#include "config.h"
#include "hela.h"

int exiting = 0;

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
		printf("%s      %-8s      %-16s\n", "CONTAINER", "PID", "SYSCALL_ID");
        	return start_trackers_without_division(output_path, exiting);
	} else if (PHASE_DIV == mode) {
		/* Print table title */
		printf("%s      %-8s      %-16s     %-24s\n", "TIME", "PID", "SYSCALL_ID", "PHASE");
		return start_trackers_with_division(output_path, exiting);
	}

	
        
}

// TODO:解析命令行参数
int parse_args(int argc, char *argv[])
{
	int opt;
	if ((opt = getopt(argc, argv, "m:")) != -1) {
		switch (opt)
		{
			case 'm':
				if (strcmp(optarg, "phase") == 0) {
					return PHASE_DIV;
					break;
				} else if (strcmp(optarg, "none") == 0) {
					return NONE;
					break;
				}
		default:
			return NONE;
			break;
		}
	}
	return NONE;
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