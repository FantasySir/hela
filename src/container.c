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
<<<<<<< HEAD
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
=======

#define CON_MNTNS_PIN_PATH              "/sys/fs/bpf/con_mntns"
#define MAX_CON                         500
#define BATCH                           8

// TODO: 完善下面的结构体，把skel和seq都传进去
struct event_ctx {
        struct syscall_bpf *ctx;
        SEQ *seq;
>>>>>>> refs/remotes/origin/master
};

// static struct phase_bpf *start_container_tracker()
// {
// 	struct phase_bpf *skel;
//         int err;

//         /* load & verify ebpf applications */
//         skel = phase_bpf__open();
//         if (!skel) {
//           	fprintf(stderr,
//                 	  "Failed to open and load container tracker skeleton\n");
// 		return NULL;
//         }
//         /* load & verify bpf prog */
//         err = phase_bpf__load(skel);
//         if (err) {
// 		fprintf(stderr, "Failed to load and verify container tracker bpf skeleton\n");
// 		goto cleanup;
//         }

//         /* attach uprobe */
//         err = phase_bpf__attach(skel);
//         if (err) {
// 		fprintf(stderr, "Failed to attach BPF skeleton\n");
// 		goto cleanup;
// 	}
//         return skel;

// cleanup:
// 	phase_bpf__destroy(skel);
//         return skel;
// }

<<<<<<< HEAD
static struct process_bpf *open_load_process_skel()
{
        struct process_bpf *skel;
=======
static struct process_bpf *start_process_tracker()
{
	struct process_bpf *skel;
>>>>>>> refs/remotes/origin/master
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
<<<<<<< HEAD
		    fprintf(stderr, "Failed to load and verify container tracker bpf skeleton\n"); 
		    goto cleanup;
        }

        return skel;

cleanup:
	process_bpf__destroy(skel);
        return skel;
}

static int *attach_process_skel(struct process_bpf *skel)
{
        int err = 0;
=======
		    fprintf(stderr, "Failed to load and verify container tracker bpf skeleton\n");
		    goto cleanup;
        }

        err = bpf_map__pin(skel->maps.container_mntns, CON_MNTNS_PIN_PATH);
        if (err) {
                hela_error("Failed to pin shared map of : container_mntns\n");
        }

        /* attach uprobe */
>>>>>>> refs/remotes/origin/master
        err = process_bpf__attach(skel);
        if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}
<<<<<<< HEAD
        return err;

cleanup:
	process_bpf__destroy(skel);
        return err;
}

// static struct process_bpf *start_process_tracker()
// {
// 	struct process_bpf *skel;
//         int err;

//         /* load & verify ebpf applications */
//         skel = process_bpf__open();
//         if (!skel) {
//           	fprintf(stderr,
//                 	  "Failed to open and load container tracker skeleton\n");
// 		return NULL;
//         }
//         /* load & verify bpf prog */
//         err = process_bpf__load(skel);
//         if (err) {
// 		    fprintf(stderr, "Failed to load and verify container tracker bpf skeleton\n"); 
// 		    goto cleanup;
//         }

//         // err = bpf_map__pin(skel->maps.container_mntns, CON_MNTNS_PIN_PATH);
//         // if (err) {
//         //         printf(stderr, "Failed to pin shared map of : container_mntns\n");
//         // }

//         /* attach uprobe */
//         err = process_bpf__attach(skel);
//         if (err) {
// 		fprintf(stderr, "Failed to attach BPF skeleton\n");
// 		goto cleanup;
// 	}
//         return skel;

// cleanup:
// 	process_bpf__destroy(skel);
//         return skel;
// }


static struct syscall_bpf *open_load_syscall_skel()
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

        /* load & verify bpf prog */
        err = syscall_bpf__load(skel);
        if (err) {
		fprintf(stderr, "Failed to load and verify container tracker bpf skeleton\n");
		goto cleanup;
        }

        return skel;

cleanup:
	syscall_bpf__destroy(skel);
        return skel;
}

static int attach_syscall_skel(struct syscall_bpf *skel)
{
        int err = 0;
        
        /* attach uprobe */
        err = syscall_bpf__attach(skel);
        if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}
        return err;

cleanup:
	syscall_bpf__destroy(skel);
        return err;
=======
        return skel;

cleanup:
	process_bpf__destroy(skel);
        return skel;
>>>>>>> refs/remotes/origin/master
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

<<<<<<< HEAD
        // /* Reuse pin */
        // int shared_fd = bpf_obj_get(CON_MNTNS_PIN_PATH);
        // err = bpf_map__reuse_fd(skel->maps.container_mntns, shared_fd);
        // if (err) {
        //         hela_error("Failed to reuse map : container_mntns");
        // }
=======
        /* Reuse pin */
        int shared_fd = bpf_obj_get(CON_MNTNS_PIN_PATH);
        err = bpf_map__reuse_fd(skel->maps.container_mntns, shared_fd);
        if (err) {
                hela_error("Failed to reuse map : container_mntns");
        }
>>>>>>> refs/remotes/origin/master

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

<<<<<<< HEAD
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
=======
static clear_pin_file()
{
        char pin_file_path = CON_MNTNS_PIN_PATH;
        if (remove(pin_file_path) == 0) {
                hela_info("Pin path init finished!\n");
        } else {
                hela_info("Pin path remove failed!\n");
        }
}

static int handle_event(void *v_ctx, void *data, size_t data_sz)
{
        struct event_ctx *ctx = (struct event_ctx *)v_ctx;
        int syscall_fd;
        const struct syscall_event *e = data;
>>>>>>> refs/remotes/origin/master
        // struct container_process cp;
        int err = 0;
        struct tm *tm;
        char ts[32];
        time_t t;
        int pid = e->pid;
<<<<<<< HEAD
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
        
        
=======
        struct syscall_bpf *syscall_skel = (struct syscall_bpf *)ctx->ctx;
        // SEQ *seq = (SEQ *)ctx->seq;
        // char *combine_seq[25] = { 0 };
        // int combine_seq_len = -1;
        // char seq_dig[32] = { 0 };
        unsigned long mntns = e->mntns;
        unsigned long count;
>>>>>>> refs/remotes/origin/master
        // struct phase_bpf *phase_skel = (struct phase_bpf *)ctx;

        /* Time stamp collect */
        time(&t);
        tm = localtime(&t);
        strftime(ts, sizeof(ts), "%H:%M:%S", tm);

<<<<<<< HEAD
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
=======
        // hela_info("Success into handle!!!\n");

        syscall_fd = bpf_map__fd(syscall_skel->maps.container_mntns);
        err = bpf_map_lookup_elem(syscall_fd, &mntns, &count);
        if (err) {
                hela_error("Cannot get mount namespace from syscall hook");
        }

        /* Sequence dealer */

        // update_syscall_seq(seq, e->syscall_id);
        // if (queueIsFull(seq)) {
        //         combine_seq_len = combine_sequence(seq, &combine_seq);
        //         digest_gen(combine_seq, combine_seq_len, seq_dig);
>>>>>>> refs/remotes/origin/master
        // }
        

        /* Sequence dealer end*/

        printf("%s          %s        %u        %s\n", ts, e->comm, pid, syscall_names_x86_64[e->syscall_id]);
        // printf("seq is : %d", seq->data[seq->rear]);
<<<<<<< HEAD
        // free(combine_seq);
=======
>>>>>>> refs/remotes/origin/master
        return 0;
}

int start_trackers(char *output_path, int exiting)
{
<<<<<<< HEAD
        // struct phase_bpf *phase_skel;
        struct process_bpf *process_skel;
=======
        struct process_bpf *process_skel;
        // struct phase_bpf *phase_skel;
>>>>>>> refs/remotes/origin/master
        struct syscall_bpf *syscall_skel;

        struct ring_buffer *syscall_rb = NULL;

        void *ctx = NULL;
        int shared_fd = 0;
        int err;
        int i;
<<<<<<< HEAD
        // const char *pin_path = CON_MNTNS_PIN_PATH;

        SEQ **syscall_seq;
        HashMap *dig_map = hash_map_create(INITIAL_TABLE_SIZE);

        /* Init */
        // clear_pin_file();
        syscall_seq = (SEQ **)malloc(sizeof(SEQ *) * MAX_CON);
        con_syscall_init(syscall_seq, BATCH, MAX_CON);
        read2map(DIGEST_LIB, dig_map);
=======
        const char *pin_path = CON_MNTNS_PIN_PATH;

        SEQ **syscall_seq;

        /* Init */
        clear_pin_file();
        syscall_seq = (SEQ **)malloc(sizeof(SEQ *) * MAX_CON);
        con_syscall_init(syscall_seq, BATCH, MAX_CON);
>>>>>>> refs/remotes/origin/master


        /* Init finished */

        // phase_skel = start_container_tracker();
<<<<<<< HEAD
        process_skel = open_load_process_skel();
        syscall_skel = open_load_syscall_skel();
        err = attach_process_skel(process_skel);
        if (err) {
                exit(1);
        }
        err = attach_syscall_skel(syscall_skel);
        if (err) {
                exit(1);
        }

        struct event_ctx ec = {
                .proc_skel = process_skel,
                .ctx = syscall_skel,
                .seq = syscall_seq,
                .map = dig_map
        };
        ctx = (void *)&ec;

=======
        process_skel = start_process_tracker();
        syscall_skel = start_syscall_tracker();

        // TODO:就在这加ctx的结构体，先睡了，八八
        struct event_ctx ec = {
                .ctx = syscall_skel,
                .seq = syscall_seq
        };
        ctx = (void *)&ec;

        shared_fd = bpf_obj_get(pin_path);
        unsigned long key;
        err = bpf_map_get_next_key(shared_fd, NULL, &key);
        if (err != 0) {
                hela_info("shared map is empty!\n");
        }

        

>>>>>>> refs/remotes/origin/master
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
<<<<<<< HEAD
        // if (process_skel) {
        //         bpf_map__unpin(process_skel->maps.container_mntns, CON_MNTNS_PIN_PATH);
        // }
        freeSeq(syscall_seq, BATCH, MAX_CON);
        // hash_map_free(dig_map);
        // free(syscall_seq);
        process_bpf__destroy(process_skel);
        syscall_bpf__destroy(syscall_skel);
        ring_buffer__free(syscall_rb);
=======
        if (process_skel) {
                bpf_map__unpin(process_skel->maps.container_mntns, CON_MNTNS_PIN_PATH);
        }
        process_bpf__destroy(process_skel);
        syscall_bpf__destroy(syscall_skel);
>>>>>>> refs/remotes/origin/master
        return err < 0 ? -err : 0;
}
