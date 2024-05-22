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

unsigned long host_mntns = 0;
unsigned long container_id = 0;

/**
 * @description: 捕获exec 的 task 并存入 rb
 * @param {struct trace_event_raw_sched_process_exec *} ctx
 * @return {int} 捕获结果，0表示结束
 */
SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	
	u64 pid = bpf_get_current_pid_tgid() >> 32;
	// u64 num = 1;
	u64 mntns;
	char comm[70];

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	mntns = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
	bpf_get_current_comm(&comm, sizeof(comm));

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
		container_id += 1;
		bpf_printk("container_id is : %lu", container_id);
		bpf_map_update_elem(&container_mntns, &mntns, &container_id, BPF_ANY);
	} else {
		bpf_printk("Sure! There has exist mnts is : %lu, proc_comm is : %s", mntns, comm);
	}
	return 0;
}