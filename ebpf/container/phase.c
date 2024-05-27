// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <stdint.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <unistd.h>
#include <stdlib.h>
#include "phase.skel.h"
#include "syscall_helper.h"
#include "phase.h"
#define warn(...) fprintf(stderr, __VA_ARGS__)

int parse_args(int argc, char *argv[])
{
	int opt;
	if ((opt = getopt(argc, argv, "m:")) != -1) {
		switch (opt)
		{
			case 'm':
				if (strcmp(optarg, "id") == 0) {
					return SYS_ID;
					break;
				} else if (strcmp(optarg, "name") == 0) {
					return SYS_NAME;
					break;
				}
		default:
			return SYS_ID;
			break;
		}
	}
	return SYS_ID;
}


static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
			   va_list args)
{
	return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct syscall_event *e = data;
	int err = 0;
	int mode = *(int *)ctx;
	
	const unsigned long mntns = e->mntns;
	const int pid = e->pid;
	const int ppid = e->ppid;
	const unsigned int syscall_id = e->syscall_id;
	const volatile int state = e->state;

	if (syscall_id < 0 || syscall_id >= syscall_names_x86_64_size) {
		return 0;
	}
	
	if (SYS_ID == mode) {
		printf("%d,%d,%u,%u,%d\n", pid, ppid, syscall_id, mntns, state);
	} else if (SYS_NAME == mode) {
		printf("%d,%d,%s,%u,%d\n", pid, ppid, syscall_names_x86_64[syscall_id], mntns, state);
	}
	return 0;
}

int main(int argc, char **argv)
{
	struct phase_bpf *skel;
	int err;
	char *runc_path = "/usr/bin/runc";
	struct ring_buffer *syscall_rb = NULL;
	void *ctx = NULL;
	int mode;

	// select mode
	mode = parse_args(argc, argv);

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);
	printf("hi!\n");
	/* Load and verify BPF application */
	skel = phase_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}
	printf("hi2!\n");
	/* Load & verify BPF programs */
	err = phase_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		perror("load error");
		goto cleanup;
	}
	printf("hi3!\n");
	err = phase_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}
	printf("hi4!\n");

	// start
        skel->links.start = bpf_program__attach_uprobe(skel->progs.start, false, -1, runc_path, 0x159600);
        err = libbpf_get_error(skel->links.start);
        if (err) {
                fprintf(stderr, "Failed to attach runc start!\n");
                goto cleanup;
        }

        // init
	skel->links.runc_init = bpf_program__attach_uprobe(skel->progs.runc_init,
	false,-1,runc_path,0x442520);
	err = libbpf_get_error(skel->links.runc_init);
	if (err) {
		fprintf(stderr, "Failed to attach uprobe in init!!!\n");
		goto cleanup;
	}


	skel->links.read_fifofd = bpf_program__attach_uprobe(skel->progs.read_fifofd,
	false,-1,runc_path,0x420d56);
	err = libbpf_get_error(skel->links.read_fifofd);
	if (err) {
		fprintf(stderr, "Failed to attach uprobe!\n");
		goto cleanup;
	}

	ctx = (void *)(&mode);
	syscall_rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, ctx, NULL);
	if (!syscall_rb) {
		err = -1;
                fprintf(stderr, "Failed to create ring buffer!\n");
                goto cleanup;
	}

	while(!exiting) {
		err = ring_buffer__poll(syscall_rb, 100);
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			sprintf(stderr, "polling ring_buffer: %d\n", err);
			break;
		}
	}



cleanup:
	/* Clean up */
	phase_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}