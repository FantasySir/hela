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

int main(int argc, char **argv)
{
	struct process_bpf *skel;
	struct process_env process_env;
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);
	process_env.exiting = &exiting;
	return start_process_tracker(process_env, skel, NULL);
}