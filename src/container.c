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

#include "../ebpf/process/process.h"
#include "./.output/process.skel.h"
#include "../ebpf/syscall/syscall.h"
#include "./.output/syscall.skel.h"
#include "../ebpf/container/phase.h"
#include "./.output/phase.skel.h"
#include "../ebpf/syscall/syscall_helper.h"

#include "data_dealer.h"
#include "hashmap.h"
#include "file_dealer.h"

// #define CON_MNTNS_PIN_PATH              "/sys/fs/bpf/con_mntns"
#define DIGEST_LIB                      "../test/digest_lib/mysqld"
#define MAX_CON                         500
#define BATCH                           8



struct event_ctx {
        struct process_bpf *proc_skel;
        struct syscall_bpf *ctx;
        SEQ **seq;
        HashMap *map;
};

static struct phase_bpf *start_container_tracker()
{
	struct phase_bpf *skel;
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

        // err = bpf_map__pin(skel->maps.container_mntns, CON_MNTNS_PIN_PATH);
        // if (err) {
        //         printf(stderr, "Failed to pin shared map of : container_mntns\n");
        // }

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
        skel = syscall_bpf__open();
        if (!skel) {
          	fprintf(stderr,
                	  "Failed to open and load container tracker skeleton\n");
		return NULL;
        }

        // /* Reuse pin */
        // int shared_fd = bpf_obj_get(CON_MNTNS_PIN_PATH);
        // err = bpf_map__reuse_fd(skel->maps.container_mntns, shared_fd);
        // if (err) {
        //         hela_error("Failed to reuse map : container_mntns");
        // }

        /* load & verify bpf prog */
        err = syscall_bpf__load(skel);
        if (err) {
		fprintf(stderr, "Failed to load and verify container tracker bpf skeleton\n");
		goto cleanup;
        }


        /* attach uprobe */
        err = syscall_bpf__attach(skel);
        if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}
        return skel;

cleanup:
	syscall_bpf__destroy(skel);
        return skel;
}

// static clear_pin_file()
// {
//         char pin_file_path = CON_MNTNS_PIN_PATH;
//         if (remove(pin_file_path) == 0) {
//                 hela_info("Pin path init finished!\n");
//         } else {
//                 hela_info("Pin path remove failed!\n");
//         }
// }

static int handle_event(void *v_ctx, void *data, size_t data_sz)
{
        const struct event_ctx *ctx = (struct event_ctx *)v_ctx;
        int fd;
        const unsigned long count = 0;
        const struct syscall_event *e = data;
        const unsigned long mntns = e->mntns;
        // struct container_process cp;
        int err = 0;
        struct tm *tm;
        char ts[32];
        time_t t;
        int pid = e->pid;
        // struct syscall_bpf *syscall_skel = (struct syscall_bpf *)ctx->ctx;
        struct process_bpf *process_skel = (struct process_bpf *)ctx->proc_skel;

        if (e->syscall_id < 0 || e->syscall_id >= syscall_names_x86_64_size)
		return 0;
        
        fd = bpf_map__fd(process_skel->maps.container_mntns);
        err = bpf_map_lookup_elem(fd, &mntns, &count);
        // if (err) {
        //         hela_error("Cannot get mntns from process skel!\n");
        // }
        if (!count) {
                // hela_info("Not container proc, proc is : %s, mntns is : %lu, count is : %ld.\n", e->comm, mntns, count);
                return 0;
        }
        // hela_info("count is : %ld\n", count);

        // SEQ **seq = (SEQ **)ctx->seq;
        // char *combine_seq = (char *)malloc(sizeof(char) * 25);
        // int combine_seq_len = -1;
        // char seq_dig[65] = { 0 };
        
        
        // struct phase_bpf *phase_skel = (struct phase_bpf *)ctx;

        /* Time stamp collect */
        time(&t);
        tm = localtime(&t);
        strftime(ts, sizeof(ts), "%H:%M:%S", tm);

        /* Sequence dealer */

        // update_syscall_seq(seq[0], e->syscall_id);
        // if (queueIsFull(seq[0])) {
        //         combine_seq_len = combine_sequence(seq[0], &combine_seq);
        //         digest_gen(combine_seq, combine_seq_len, seq_dig);
        //         if (!hash_map_search(ctx->map, seq_dig)) {
        //                 // hela_error("Unexpected syscall occured!!\n");
        //         }
        //         // hela_info("%s", seq_dig);
        //         // Check deviation
        // }
        // if (sequence_batch_check(seq[0])) { // 若已经满足一个batch的数量
        //         if (seq[0]->deviation > 8) {
        //                 hela_info("One batch over! unexpected syscall / batch syscall : %d / %d", seq[0]->deviation, CHECKBATCH);
        //         }
        //         seq[0]->deviation = 0;
        //         seq[0]->checkCount = 0;
        // }
        

        /* Sequence dealer end*/

        printf("%s          %s        %u        %s\n", ts, e->comm, pid, syscall_names_x86_64[e->syscall_id]);
        // printf("seq is : %d", seq->data[seq->rear]);
        // free(combine_seq);
        return 0;
}

int start_trackers(char *output_path, int exiting)
{
        // struct phase_bpf *phase_skel;
        struct process_bpf *process_skel;
        struct syscall_bpf *syscall_skel;

        struct ring_buffer *syscall_rb = NULL;

        void *ctx = NULL;
        int shared_fd = 0;
        int err;
        int i;
        // const char *pin_path = CON_MNTNS_PIN_PATH;

        SEQ **syscall_seq;
        HashMap *dig_map = hash_map_create(INITIAL_TABLE_SIZE);

        /* Init */
        // clear_pin_file();
        syscall_seq = (SEQ **)malloc(sizeof(SEQ *) * MAX_CON);
        con_syscall_init(syscall_seq, BATCH, MAX_CON);
        read2map(DIGEST_LIB, dig_map);


        /* Init finished */

        // phase_skel = start_container_tracker();
        process_skel = start_process_tracker();
        syscall_skel = start_syscall_tracker();

        struct event_ctx ec = {
                .proc_skel = process_skel,
                .ctx = syscall_skel,
                .seq = syscall_seq,
                .map = dig_map
        };
        ctx = (void *)&ec;

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
                        hela_error("polling perf buffer: %d\n", err);
                        break;
                }
        }

cleanups:
        // phase_bpf__destroy(phase_skel);
        freeSeq(syscall_seq, BATCH, MAX_CON);
        hash_map_free(dig_map);
        free(syscall_seq);
        process_bpf__destroy(process_skel);
        syscall_bpf__destroy(syscall_skel);
        ring_buffer__free(syscall_rb);
        return err < 0 ? -err : 0;
}
