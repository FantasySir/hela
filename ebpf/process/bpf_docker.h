/*
 Copyright (c) 2023 Broin All rights reserved.
 Use of this source code is governed by a BSD-style
 license that can be found in the LICENSE file.
 */

#ifndef BPF_DOCKER__H
#define BPF_DOCKER__H

/**
 * @description: 获取当前任务的 mount ns id
 * @return {u32} 成功时返回 ns id， 失败时返回 0
 */
static __always_inline u32 get_current_mnt_ns_id()
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
	return task->nsproxy->mnt_ns->ns.inum;
}

/**
 * @description: 获取当前任务的 pid ns id
 * @return {u32} 成功时返回 ns id， 失败时返回 0
 */
static __always_inline u32 get_current_pid_ns_id()
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
	return task->thread_pid->numbers[0].ns->ns.inum;
}

/**
 * @description: 获取当前任务的 user ns id
 * @return {u32} 成功时返回 ns id， 失败时返回 0
 */
static __always_inline u32 get_current_user_ns_id()
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
	return task->cred->user_ns->ns.inum;
}

/**
 * @description: 初始化进程信息
 * @return {*} 无
 */
static __always_inline void fill_event_basic(pid_t pid, struct task_struct *task,
					     struct process_event *e)
{
	e->common.pid = pid;
	e->common.ppid = BPF_CORE_READ(task, real_parent, tgid);
	e->common.cgroup_id = bpf_get_current_cgroup_id();
	e->common.user_namespace_id = get_current_user_ns_id();
	e->common.pid_namespace_id = get_current_pid_ns_id();
	e->common.mount_namespace_id = get_current_mnt_ns_id();
}

#endif // !BPF_DOCKER__H