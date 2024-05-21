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
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "./process_tracker.h"
#include "process.skel.h"

volatile int exiting = 0;

static void sig_handler(int sig)
{
	exiting = 1;
}

<<<<<<< HEAD
=======
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !process_env.verbose) {
		return 0;
	}
	return vfprintf(stderr, format, args);
}

static void print_table_data(const struct process_event *e)
{
	print_basic_info((const struct common_event *)e, 0);

	if (e->exit_event) {
		printf("%-5s %-16s [%u]", "EXIT", e->comm, e->exit_code);
		if (e->duration_ns)
			printf("(%llums)", e->duration_ns / 1000000);
		printf("\n");
	} else {
		printf("%-5s %-16s %s\n", "EXEC", e->comm, e->filename);
	}
}

static void print_header(void)
{
	print_table_header(headers, process_env.is_csv);
}

static void print_csv_data(const struct process_event *e)
{
	print_basic_info((const struct common_event *)e, 1);

	if (e->exit_event) {
		printf("%s, %s, %u,", "EXIT", e->comm, e->exit_code);
		if (e->duration_ns)
			printf("%llu", e->duration_ns / 1000000);
		printf("\n");
	} else {
		printf("%s, %s, %s\n", "EXEC", e->comm, e->filename);
	}
}

static void copy_process_event(struct process_event *dest, const struct process_event *src)
{
	dest->common = src->common;
	dest->duration_ns = src->duration_ns;
	dest->exit_code = src->exit_code;
	strcpy(dest->filename, src->filename);
	strcpy(dest->comm, src->comm);
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	printf("Into event handle!\n");
	const struct process_event *e = data;
		print_csv_data(e);
	if (process_env.is_csv) {
	} else {
		print_table_data(e);
	}
	return 0;
}

>>>>>>> refs/remotes/origin/master
int main(int argc, char **argv)
{
	struct process_bpf *skel;
	struct process_env process_env;
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);
	process_env.exiting = &exiting;
	return start_process_tracker(process_env, skel, NULL);
}