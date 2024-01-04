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
#define warn(...) fprintf(stderr, __VA_ARGS__)

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

int main(int argc, char **argv)
{
	struct phase_bpf *skel;
	int err;
	char *runc_path = "/home/lsh/uprobe-container/containers/mycontainer1/runc";
	char *runc_sys = "/usr/bin/runc";
	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Load and verify BPF application */
	skel = phase_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Load & verify BPF programs */
	err = phase_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		perror("load error");
		goto cleanup;
	}
	
	err = phase_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}
	if(strcmp(argv[1],"local")==0){
		skel->links.container_create = bpf_program__attach_uprobe(skel->progs.container_create,
		false,-1,runc_path,0x42dce0);
		err = libbpf_get_error(skel->links.container_create);
		if (err) {
			fprintf(stderr, "Failed to attach uprobe!\n");
			goto cleanup;
		}
		skel->links.bootstrap1 = bpf_program__attach_uprobe(skel->progs.bootstrap1,
		false,-1,runc_path,0x436780);
		err = libbpf_get_error(skel->links.bootstrap1);
		if (err) {
			fprintf(stderr, "Failed to attach uprobe!\n");
			goto cleanup;
		}
		skel->links.runc_init = bpf_program__attach_uprobe(skel->progs.runc_init,
		false,-1,runc_path,0x442520);
		err = libbpf_get_error(skel->links.runc_init);
		if (err) {
			fprintf(stderr, "Failed to attach uprobe!\n");
			goto cleanup;
		}
		skel->links.runc_containerInit = bpf_program__attach_uprobe(skel->progs.runc_containerInit,
		false,-1,runc_path,0x42fb40);
		err = libbpf_get_error(skel->links.runc_containerInit);
		if (err) {
			fprintf(stderr, "Failed to attach uprobe!\n");
			goto cleanup;
		}
		skel->links.read_fifofd = bpf_program__attach_uprobe(skel->progs.read_fifofd,
		false,-1,runc_path,0x41df05);
		err = libbpf_get_error(skel->links.read_fifofd);
		if (err) {
			fprintf(stderr, "Failed to attach uprobe!\n");
			goto cleanup;
		}
		skel->links.container_config = bpf_program__attach_uprobe(skel->progs.container_config,
		false,-1,runc_path,0x4a6f96);
		err = libbpf_get_error(skel->links.container_config);
		if (err) {
			fprintf(stderr, "Failed to attach uprobe!\n");
			goto cleanup;
		}
	}
	else if(strcmp(argv[1],"sys")==0){
		skel->links.container_create = bpf_program__attach_uprobe(skel->progs.container_create,
		false,-1,runc_sys,0x42dce0);
		err = libbpf_get_error(skel->links.container_create);
		if (err) {
			fprintf(stderr, "Failed to attach uprobe!\n");
			goto cleanup;
		}
		skel->links.bootstrap1 = bpf_program__attach_uprobe(skel->progs.bootstrap1,
		false,-1,runc_sys,0x436780);
		err = libbpf_get_error(skel->links.bootstrap1);
		if (err) {
			fprintf(stderr, "Failed to attach uprobe!\n");
			goto cleanup;
		}
		skel->links.runc_init = bpf_program__attach_uprobe(skel->progs.runc_init,
		false,-1,runc_sys,0x442520);
		err = libbpf_get_error(skel->links.runc_init);
		if (err) {
			fprintf(stderr, "Failed to attach uprobe!\n");
			goto cleanup;
		}
		skel->links.runc_containerInit = bpf_program__attach_uprobe(skel->progs.runc_containerInit,
		false,-1,runc_sys,0x42fb40);
		err = libbpf_get_error(skel->links.runc_containerInit);
		if (err) {
			fprintf(stderr, "Failed to attach uprobe!\n");
			goto cleanup;
		}
		skel->links.read_fifofd = bpf_program__attach_uprobe(skel->progs.read_fifofd,
		false,-1,runc_sys,0x41df05);
		err = libbpf_get_error(skel->links.read_fifofd);
		if (err) {
			fprintf(stderr, "Failed to attach uprobe!\n");
			goto cleanup;
		}
		skel->links.container_config = bpf_program__attach_uprobe(skel->progs.container_config,
		false,-1,runc_sys,0x4a6f96);
		err = libbpf_get_error(skel->links.container_config);
		if (err) {
			fprintf(stderr, "Failed to attach uprobe!\n");
			goto cleanup;
		}
		skel->links.join_namespaces = bpf_program__attach_uprobe(skel->progs.join_namespaces,
		false,-1,runc_sys,0x4f1710);
		err = libbpf_get_error(skel->links.join_namespaces);
		if (err) {
			fprintf(stderr, "Failed to attach uprobe!\n");
			goto cleanup;
		}
	}
	/*skel->links.Exec = bpf_program__attach_kprobe(skel->progs.Exec,false,"__x64_sys_execve");
	err = libbpf_get_error(skel->links.Exec);
	if (err) {
		fprintf(stderr, "Failed to attach uprobe!\n");
		goto cleanup;
	}*/
	while (!exiting) {
		sleep(1);
		
	}
cleanup:
	/* Clean up */
	phase_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}