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

#include "process.h"
#include "process_tracker.h"
#include "process.skel.h"

#define NS_LEN 4

static const char *headers[] = { "stat", "comm", "filename/exitcode", "duration",
				 (const char *)((void *)0) };

static struct process_env process_env = { 0 };

static const char argp_program_doc[] =
	"eBPF process tracing application. \n"
	"\n"
	"It tracess process start and exits and shows associated \n"
	"information (filename, process duration, PID and PPID, etc.)."
	"\n"
	"USAGE: ./process [-d <min-duration-ms>] [-v]\n";

const char *namespaces[] = { "cgroup", "user", "pid", "mnt" };

static struct process_bpf *skel;

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Process ID to trace" },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "csv", 'c', NULL, 0, "Output in the CSV format" },
	{ "NULL", 'h', NULL, OPTION_HIDDEN, "Show full help" },
	{ "duration", 'd', "DURATION-MS", 0, "Minimum process duration (ms) to report" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	pid_t pid;
	switch (key) {
	case 'v':
		process_env.verbose = 1;
		break;
	case 'p':
		errno = 0;
		pid = strtol(arg, NULL, 10);
		if (errno || pid <= 0) {
			fprintf(stderr, "Invalid PID: %s\n", arg);
			argp_usage(state);
		}
		process_env.target_pid = pid;
		break;
	case 'd':
		errno = 0;
		process_env.min_duration_ms = strtol(arg, NULL, 10);
		if (errno || process_env.min_duration_ms <= 0) {
			fprintf(stderr, "Invalid duration: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'C':
		process_env.is_csv = true;
		break;
	case ARGP_KEY_ARG:
		argp_usage(state);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
		break;
	}
	return 0;
}

static const struct argp argp = {
	.options = opts,
	.parser = parse_arg,
	.doc = argp_program_doc,
};

volatile int exiting = 0;

static void sig_handler(int sig)
{
	exiting = 1;
}

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
	if (process_env.is_csv) {
		print_csv_data(e);
	} else {
		print_table_data(e);
	}
}

int main(int argc, char **argv)
{
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);
	print_header();
	process_env.exiting = &exiting;
	return start_process_tracker(handle_event, libbpf_print_fn, process_env, skel, NULL);
}