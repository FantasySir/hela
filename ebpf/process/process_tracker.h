/*
 Copyright (c) 2023 Broin All rights reserved.
 Use of this source code is governed by a BSD-style
 license that can be found in the LICENSE file.
 */

#include <argp.h>
#include <stdio.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <sys/resource.h>
#include <time.h>

#include "process.skel.h"

// #define CON_MNTNS_PIN_PATH              "/sys/fs/bpf/con_mntns"

struct process_env {
	int verbose;
	int is_csv;
	pid_t target_pid;
	pid_t exclude_current_ppid;
	long min_duration_ms;
	volatile int *exiting;
};

static int start_process_tracker( struct process_env env,
				 struct process_bpf *skel, void *ctx)
{
	// struct ring_buffer *rb = NULL;
	int err;

	if (!env.exiting) {
		fprintf(stderr, "env.exiting is not set.\n");
		return -1;
	}
	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	skel = process_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* 使用最小持续时间参数化BPF代码 */
	// skel->rodata->min_duration_ns = env.min_duration_ms * 1000000ULL;
	// skel->rodata->target_pid = env.target_pid;
	// skel->rodata->exclude_current_ppid = env.exclude_current_ppid;

	/* 加载并验证BPF程序 */
	err = process_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton.\n");
		goto cleanup;
	}

	//   err = bpf_map__pin(skel->maps.container_mntns, CON_MNTNS_PIN_PATH);
        // if (err) {
        //         fprintf(stderr,"Failed to pin shared map of : container_mntns\n");
        // }

	/* 挂载监控点 */
	err = process_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton.\n");
		goto cleanup;
	}

	/* rb轮询 */
	// rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, ctx, NULL);
	// if (!rb) {
	// 	err = -1;
	// 	fprintf(stderr, "Failed to create ring buffer\n");
	// 	goto cleanup;
	// }
	// while (!(*env.exiting)) {
	// 	err = ring_buffer__poll(rb, 100);
	// 	// ctrl + c
	// 	if (err == -EINTR) {
	// 		err = 0;
	// 		break;
	// 	}
	// 	if (err < 0) {
	// 		printf("Error polling perf buffer: %d\n", err);
	// 		break;
	// 	}
	// }

cleanup:
	// ring_buffer__free(rb);
	process_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}