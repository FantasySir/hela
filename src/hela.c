#include "hela.h"

int exiting = 0;

static void sig_handler(int sig)
{
	exiting = 1;
}

int container_syscall_tracing(char *output_path)
{
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Print table title */
        printf("%s      %-8s      %-16s\n", "CONTAINER", "PID", "SYSCALL_ID");
        return start_trackers(output_path, exiting);
}

int main(int argc, char **argv)
{
	// TODO:
        int ret;

        /* Init */

        /* Tracing */
        container_syscall_tracing(NULL);
	ret = 0;
	return ret;
}