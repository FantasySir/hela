/*
 Copyright (c) 2023 Broin All rights reserved.
 Use of this source code is governed by a BSD-style
 license that can be found in the LICENSE file.
 */

/*
捕捉进程fork操作


*/

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/bpf.h>

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, u32);
	__type(value, struct docker_event);
} processes SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC("maps");

SEC("tracepoint/sched/sched_process_fork")
int tp__sched_proc_fork(struct trace_event_raw_sched_process_fork *args)
{
	
	return 0;
}