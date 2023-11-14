/*
 Copyright (c) 2023 Broin All rights reserved.
 Use of this source code is governed by a BSD-style
 license that can be found in the LICENSE file.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "process.h"
#include "../bpf_docker.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, pid_t);
	__type(value, u64);
} exec_start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, pid_t);
	__type(value, struct process_event);
} process SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

const volatile unsigned long long min_duration_ns = 0;
const volatile unsigned long long target_pid = 0;
const volatile unsigned long long exclude_current_ppid = 0;

/**
 * @description: 捕获exec 的 task 并存入 rb
 * @param {struct trace_event_raw_sched_process_exec *} ctx
 * @return {int} 捕获结果，0表示结束
 */
SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	struct task_struct *task;
	unsigned fname_off;
	struct process_event *e;
	pid_t pid;
	u64 ts;

	pid = bpf_get_current_pid_tgid() >> 32;
	if (target_pid && pid != target_pid) {
		return 0;
	}
	ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&exec_start, &pid, &ts, BPF_ANY);

	if (min_duration_ns) {
		return 0;
	}

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e) {
		return 0;
	}

	task = (struct task_struct *)bpf_get_current_task();
	if (exclude_current_ppid) {
		if (exclude_current_ppid == BPF_CORE_READ(task, real_parent, tgid)) {
			return 0;
		}
	}
	fill_event_basic(pid, task, e);

	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	e->exit_event = 0;
	e->pid = pid;
	fname_off = ctx->__data_loc_filename & 0xFFFF;
        bpf_probe_read_str(e->filename, sizeof(e->filename),
                           (void *)ctx + fname_off);
        bpf_map_update_elem(&process, &pid, e, BPF_ANY);

	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template *ctx)
{
	struct task_struct *task;
	struct process_event *e;
	pid_t pid, tid;
	unsigned int id, ts, *start_ts, duration_ns = 0;

	id = bpf_get_current_pid_tgid();
	pid = id >> 32;
	tid = (u32)id;
	if (target_pid && pid != target_pid)
		return 0;

	// 忽略线程退出
	if (pid != tid)
		return 0;

	// 如果该进程被exec_start结构体记录，则计算其生命周期
	start_ts = bpf_map_lookup_elem(&exec_start, &pid);
	if (start_ts)
		duration_ns = bpf_ktime_get_ns() - *start_ts;
	else if (min_duration_ns)
		return 0;
	bpf_map_delete_elem(&exec_start, &pid);

	// 如果生存时间过少，则直接返回
	if (min_duration_ns && duration_ns < min_duration_ns)
		return 0;

	// 申请rb缓存
	bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	// 填充进程信息
	task = (struct task_struct *)bpf_get_current_task();
	if (exclude_current_ppid) {
		if (exclude_current_ppid == BPF_CORE_READ(task, real_parent, tgid)) {
			return 0;
		}
	}
	fill_event_basic(pid, task, e);

	e->exit_event = 1;
	e->duration_ns = duration_ns;
	e->pid = pid;
	e->exit_code = (BPF_CORE_READ(task, exit_code) >> 8) & 0xFF;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	bpf_map_delete_elem(&process, &pid);

	// 发送进程数据数据去用户空间
	bpf_ringbuf_submit(e, 0);
	bpf_map_delete_elem(&process, &pid);

	return 0;
}