/*
 Copyright (c) 2023 Broin All rights reserved.
 Use of this source code is governed by a BSD-style
 license that can be found in the LICENSE file.
 */


#include <vmlinux.h>
#include <asm-generic/errno.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#include "syscall.h"
#include "../bpf_docker.h"

#define MAX_COMM_LEN 64
#define MAX_ENTRIES 8 * 1024
#define MAX_SYSCALLS 1024

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, MAX_ENTRIES);
        __type(key, u32);                       // PID
        __type(value, u8[MAX_SYSCALLS]);        // syscall id
} syscalls SEC(".maps");                        // process syscall list

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, MAX_ENTRIES);
        __type(key, u32);                       // PID
        __type(value, char[MAX_COMM_LEN]);      // command name
} comms SEC(".maps");                           // proc commands

struct {
        __uint(type, BPF_MAP_TYPE_RINGBUF);
        __uint(max_entries, 1 << 24);
} events SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_CGROUP_ARRAY);
        __type(key, u32);
        __type(value, u32);
        __uint(max_entries, 1);
} cgroup_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1 << 24);
	__type(key, u64);
	__type(value, u64);
} container_mntns SEC(".maps");


const volatile int filter_cg = 0;
const volatile unsigned char filter_report_times = 0;
const volatile pid_t filter_pid = 0;
const volatile unsigned long long min_duration_ns = 0;
volatile unsigned long long last_ts = 0;

void __always_inline submit_event(struct task_struct *task, u32 pid, u32 mntns, u32 syscall_id, unsigned char times)
{
        struct syscall_event *event = bpf_ringbuf_reserve(&events, sizeof(struct syscall_event), 0);
        if (!event) {
                // 没有足够rb空间
                return ;
        }

        event->pid = pid;
        event->ppid = BPF_CORE_READ(task, real_parent, tgid);
        event->mntns = mntns;
        event->syscall_id = syscall_id;
        event->occur_times = times;
        bpf_get_current_comm(&event->comm, sizeof(event->comm));

        bpf_ringbuf_submit(event, 0);
}

SEC("tracepoint/raw_syscalls/sys_enter")
int sys_enter(struct trace_event_raw_sys_enter *args) 
{
        // id 合理性检查
        u32 syscall_id = args->id;
        if (syscall_id < 0 || syscall_id >= MAX_SYSCALLS)
                return 0;

        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        u64 mntns = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
        
        /* mntns Filter */
        if (!bpf_map_lookup_elem(&container_mntns, &mntns)) {
                // bpf_printk("syscall not in container...");
                return 0;
        }

        if (bpf_map_lookup_elem(&container_mntns, &mntns)) {
                bpf_printk("Get host mount namespace from process tracker... mount namespace id is : %lu", mntns);
        }
        /* mntns filter finished */

        u32 pid = bpf_get_current_pid_tgid() >> 32;
        if (filter_pid && pid != filter_pid)
                return 0;
        if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
                return 0;

        if (0 == mntns) {
                return 0;
        }


        /* 检查进程命令 */
        char comm[MAX_COMM_LEN];
        bpf_get_current_comm(comm, sizeof(comm));
        if (!bpf_map_lookup_elem(&comms, &comm)) {
                bpf_map_update_elem(&comms, &pid, &comm, BPF_ANY);
        }

        u8 *syscall_value = bpf_map_lookup_elem(&syscalls, &pid);
        if (syscall_value) {   // 存在调用列表
                if (syscall_value[syscall_id] == 0) { // 头一次调用
                        // 提交进程系统调用事件
                        submit_event(task, pid, mntns, syscall_id, 1);
                        syscall_value[syscall_id] = 1;
                        return 0;
                } else if (filter_report_times) {
                        if (syscall_value[syscall_id] >= filter_report_times) {
                                // 调用次数大于1次，就可以放入event rb中
                                submit_event(task, pid, mntns, syscall_id,
                                             filter_report_times);
                                syscall_value[syscall_id] = 1;
                        } else {
                                syscall_value[syscall_id]++;
                        }
                } else if (min_duration_ns) {
                        u64 ts = bpf_ktime_get_ns();
                        if (syscall_value[syscall_id] < 255)
                                syscall_value[syscall_id]++;
                        if (ts - last_ts < min_duration_ns)
                          return 0;
                        last_ts = ts;
                        submit_event(task, pid, mntns, syscall_id,
                                     syscall_value[syscall_id]);
                        syscall_value[syscall_id] = 1;
                }
        } else {
                // 头一次提交事件信息
                submit_event(task, pid, mntns, syscall_id, 1);

                static const unsigned char init[MAX_SYSCALLS];
                bpf_map_update_elem(&syscalls, &pid, &init, BPF_ANY);

                u8 *const value = bpf_map_lookup_elem(&syscalls, &pid);
                if (!value) {
                        // 不应该发生，我们就直接结束掉
                        return 0;
                }
                value[syscall_id] = 1;
        }
        return 0;
}