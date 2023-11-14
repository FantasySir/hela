/*
 Copyright (c) 2023 Broin All rights reserved.
 Use of this source code is governed by a BSD-style
 license that can be found in the LICENSE file.
 */

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <argp.h>
#include <time.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "../ebpf/common.h"
#include "../ebpf/process/process.h"
#include "../ebpf/process/.output/process.skel.h"
#include "../ebpf/syscall/syscall.h"
#include "../ebpf/syscall/.output/syscall.skel.h"
#include "../ebpf/container/phase.h"
#include "../ebpf/container/.output/phase.skel.h"


static struct phase_bpf *start_container_tracker()
{
	struct phase_bpf *skel;
        struct container_process *cp;
        int err;

        /* load & verify ebpf applications */
        skel = phase_bpf__open();
        if (!skel) {
          	fprintf(stderr,
                	  "Failed to open and load container tracker skeleton\n");
		return NULL;
        }
        /* load & verify bpf prog */
        err = phase_bpf__load(skel);
        if (err) {
		fprintf(stderr, "Failed to load and verify container tracker bpf skeleton\n");
		goto cleanup;
        }

        /* attach uprobe */
        err = phase_bpf__attach(skel);
        if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}
        return skel;

cleanup:
	phase_bpf__destroy(skel);
        return skel;
}

static struct process_bpf *start_process_tracker()
{
	struct process_bpf *skel;
        struct container_process *cp;
        int err;

        /* load & verify ebpf applications */
        skel = process_bpf__open();
        if (!skel) {
          	fprintf(stderr,
                	  "Failed to open and load container tracker skeleton\n");
		return NULL;
        }
        /* load & verify bpf prog */
        err = process_bpf__load(skel);
        if (err) {
		    fprintf(stderr, "Failed to load and verify container tracker bpf skeleton\n");
		    goto cleanup;
        }

        /* attach uprobe */
        err = process_bpf__attach(skel);
        if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}
        return skel;

cleanup:
	process_bpf__destroy(skel);
        return skel;
}

static struct syscall_bpf *start_syscall_tracker()
{
	struct syscall_bpf *skel;
        int err;

        /* load & verify ebpf applications */
        skel = phase_bpf__open();
        if (!skel) {
          	fprintf(stderr,
                	  "Failed to open and load container tracker skeleton\n");
		return NULL;
        }
        /* load & verify bpf prog */
        err = phase_bpf__load(skel);
        if (err) {
		fprintf(stderr, "Failed to load and verify container tracker bpf skeleton\n");
		goto cleanup;
        }

        /* attach uprobe */
        err = phase_bpf__attach(skel);
        if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}
        return skel;

cleanup:
	phase_bpf__destroy(skel);
        return skel;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
        int con_fd;
        const struct syscall_event *e = data;
        struct container_process cp;
        int err = 0;
        struct tm *tm;
        char ts[32];
        time_t t;
        int pid = e->pid;

        /* Time stamp collect */
        time(&t);
        tm = localtime(&t);
        strftime(ts, sizeof(ts), "%H:%M:%S", tm);

        /* Judge pid in container */
        con_fd = bpf_map__fd(phase_skel->maps.Docker_ID);
        err = bpf_map_lookup_elem(con_fd, &pid, &cp);
        if (err < 0)
                return 0;

        printf("%llu, %u, %lu", cp.cid, pid, e->syscall_id);
        return 0;
}

int start_trackers(char *output_path, int exiting)
{
        struct process_bpf *process_skel;
        struct phase_bpf *phase_skel;
        struct syscall_bpf *syscall_skel;

        int con_fd;
        struct ring_buffer *syscall_rb = NULL;

        void *ctx = NULL;
        int err;

        phase_skel = start_container_tracker();
        process_skel = start_process_tracker();
        syscall_skel = start_syscall_tracker();

        syscall_rb = ring_buffer__new(bpf_map__fd(syscall_skel->maps.events), handle_event, ctx, NULL);
        if (!syscall_rb) {
                err = -1;
                fprintf(stderr, "Failed to create ring buffer!\n");
                goto cleanups;
        }

        while (!exiting) {
                err = ring_buffer__poll(syscall_rb, 100);
                if (err == -EINTR) {
                        err = 0;
                        break;
                }
                if (err < 0) {
                        printf("[Error] polling perf buffer: %d\n", err);
                        break;
                }
        }

cleanups:
        process_bpf__destroy(process_skel);
        phase_bpf__destroy(phase_skel);
        syscall_bpf__destroy(syscall_skel);
        return err < 0 ? -err : 0;
}
