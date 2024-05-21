/*
 Copyright (c) 2023 Broin All rights reserved.
 Use of this source code is governed by a BSD-style
 license that can be found in the LICENSE file.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1 << 24);
	__type(key, u64);
	__type(value, u64);
} container_mntns SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1 << 24);
	__type(key, u64);
	__type(value, u64);
} host_con_base_mntns SEC(".maps");

<<<<<<< HEAD
unsigned long host_mntns = 0;
unsigned long container_id = 0;
=======
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1 << 24);
	__type(key, u64);
	__type(value, u64);
} container_mntns SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1 << 24);
	__type(key, u64);
	__type(value, u64);
} host_con_base_mntns SEC(".maps");

const volatile unsigned long long min_duration_ns = 0;
const volatile unsigned long long target_pid = 0;
const volatile unsigned long long exclude_current_ppid = 0;
unsigned long host_mntns = 0;
unsigned long container_num = 0;
>>>>>>> refs/remotes/origin/master

/**
 * @description: 捕获exec 的 task 并存入 rb
 * @param {struct trace_event_raw_sched_process_exec *} ctx
 * @return {int} 捕获结果，0表示结束
 */
SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
<<<<<<< HEAD
	
	u64 pid = bpf_get_current_pid_tgid() >> 32;
	// u64 num = 1;
	u64 mntns;
	char comm[70];
=======
	struct task_struct *task;
	unsigned fname_off;
	struct process_event *e;
	pid_t pid;
	u64 ts;
	u64 mntns;
	char comm[70];

	task = (struct task_struct *)bpf_get_current_task();
	mntns = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
	bpf_get_current_comm(&comm, 69);

	/* filter */

	// host_con_base_mntns filter
	// dockerd mntns
	if (!host_mntns) {
		host_mntns = mntns;
	}

	

	// udevd mntns
	if ( bpf_strncmp(comm, 15, "bridge-network-") == 0 ) {
		bpf_printk("Detected bridge-network!! mntns is : %lu", mntns);
		if (!bpf_map_lookup_elem(&host_con_base_mntns, &mntns)) {
			bpf_map_update_elem(&host_con_base_mntns, &mntns, &pid, BPF_ANY);
		}
		return 0;
	}

	// dockerd
	if (bpf_strncmp(comm, 15, "containerd-shim") == 0) {
		bpf_printk("Detected shim ! mntns is : %lu", mntns);
		if (!bpf_map_lookup_elem(&host_con_base_mntns, &mntns)) {
			bpf_map_update_elem(&host_con_base_mntns, &mntns, &pid, BPF_ANY);
		}
		return 0;
	}

	if (mntns == host_mntns) {
		// bpf_printk("process not in container!");
		return 0;
	}
	if (bpf_map_lookup_elem(&host_con_base_mntns, &mntns)) {
		return 0;
	}


	// container mntns
	u64 con_num = bpf_map_lookup_elem(&container_mntns, &mntns);
	
	if (!con_num) {
		bpf_printk("Yeah! Adding new mntns! mntns is : %lu, proc_comm is : %s", mntns, comm);
		container_num += 1;
		bpf_printk("container_num is : %lu", container_num);
		con_num = container_num;
		bpf_map_update_elem(&container_mntns, &mntns, &con_num, BPF_ANY);
	} else {
		bpf_printk("Sure! There has exist mnts is : %lu, proc_comm is : %s", mntns, comm);
	}

	if (bpf_map_lookup_elem(&container_mntns, &mntns)) {
		bpf_printk("Find mntns from container, %lu, proc_comm is : %s", mntns, comm);
	}
>>>>>>> refs/remotes/origin/master

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	mntns = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
	bpf_get_current_comm(&comm, sizeof(comm));

	/* filter */

	// host_con_base_mntns filter
	// dockerd mntns
	if (!host_mntns) {
		host_mntns = mntns;
	}

<<<<<<< HEAD
	// udevd mntns
	if ( bpf_strncmp(comm, 15, "bridge-network-") == 0 ) {
		bpf_printk("Detected bridge-network!! mntns is : %lu", mntns);
		if (!bpf_map_lookup_elem(&host_con_base_mntns, &mntns)) {
			bpf_map_update_elem(&host_con_base_mntns, &mntns, &pid, BPF_ANY);
=======
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e) {
		return 0;
	}

	if (exclude_current_ppid) {
		if (exclude_current_ppid == BPF_CORE_READ(task, real_parent, tgid)) {
			return 0;
>>>>>>> refs/remotes/origin/master
		}
		return 0;
	}
<<<<<<< HEAD

	// dockerd
	if (bpf_strncmp(comm, 15, "containerd-shim") == 0) {
		bpf_printk("Detected shim ! mntns is : %lu", mntns);
		if (!bpf_map_lookup_elem(&host_con_base_mntns, &mntns)) {
			bpf_map_update_elem(&host_con_base_mntns, &mntns, &pid, BPF_ANY);
=======
	/* end filter */

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
	// u64 mntns = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);

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
>>>>>>> refs/remotes/origin/master
		}
		return 0;
	}

	if (mntns == host_mntns) {
		// bpf_printk("process not in container!");
		return 0;
	}
	if (bpf_map_lookup_elem(&host_con_base_mntns, &mntns)) {
		return 0;
	}

<<<<<<< HEAD

	// container mntns
	u64 con_num = bpf_map_lookup_elem(&container_mntns, &mntns);
	
	if (!con_num) {
		bpf_printk("Yeah! Adding new mntns! mntns is : %lu, proc_comm is : %s", mntns, comm);
		container_id += 1;
		bpf_printk("container_id is : %lu", container_id);
		bpf_map_update_elem(&container_mntns, &mntns, &container_id, BPF_ANY);
	} else {
		bpf_printk("Sure! There has exist mnts is : %lu, proc_comm is : %s", mntns, comm);
	}
=======
	/* Delete mntns from map */
	bpf_map_delete_elem(&process, &pid);
	// bpf_map_delete_elem(&container_mntns, &mntns);

	// 发送进程数据数据去用户空间
	bpf_ringbuf_submit(e, 0);
	bpf_map_delete_elem(&process, &pid);

>>>>>>> refs/remotes/origin/master
	return 0;
}