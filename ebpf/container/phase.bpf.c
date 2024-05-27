// #define BPF_NO_GLOBAL_DATA
// #define GO_PARAM1(x) BPF_CORE_READ((x), ax)
// #define GO_PARAM2(x) BPF_CORE_READ((x), bx)
// #define GO_PARAM3(x) BPF_CORE_READ((x), cx)
// #define GO_PARAM4(x) BPF_CORE_READ((x), di)
// #define GO_PARAM5(x) BPF_CORE_READ((x), si)
// #define GO_PARAM6(x) BPF_CORE_READ((x), r8)
// #define GO_PARAM7(x) BPF_CORE_READ((x), r9)
// #define GO_PARAM8(x) BPF_CORE_READ((x), r10)
// #define GO_PARAM9(x) BPF_CORE_READ((x), r11)
// #define GOROUTINE(x) BPF_CORE_READ((x), r14)
// #define GO_SP(x) BPF_CORE_READ((x), sp)
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "phase.h"

#define MAX_ENTRIES 8 * 1024
#define MAX_COMM_LEN 64
#define MAX_SYSCALLS 1024

// void* go_get_argument_by_reg(struct pt_regs *ctx, int index) {
//     switch (index) {
//         case 1:
//             return (void*)GO_PARAM1(ctx);
//         case 2:
//             return (void*)GO_PARAM2(ctx);
//         case 3:
//             return (void*)GO_PARAM3(ctx);
//         case 4:
//             return (void*)GO_PARAM4(ctx);
//         case 5:
//             return (void*)GO_PARAM5(ctx);
//         case 6:
//             return (void*)GO_PARAM6(ctx);
//         case 7:
//             return (void*)GO_PARAM7(ctx);
//         case 8:
//             return (void*)GO_PARAM8(ctx);
//         case 9:
//             return (void*)GO_PARAM9(ctx);
//         default:
//             return NULL;
//     }
// }
// void* go_get_argument_by_stack(struct pt_regs *ctx, int index) {
//     void* ptr = 0;
//     bpf_probe_read(&ptr, sizeof(ptr), (void *)(PT_REGS_SP(ctx)+(index*8)));
//     return ptr;
// }

// void* go_get_argument(struct pt_regs *ctx,bool is_register_abi, int index) {
//     if (is_register_abi) {
//         return go_get_argument_by_reg(ctx, index);
//     }
//     return go_get_argument_by_stack(ctx, index);
// }
struct {
        __uint(type, BPF_MAP_TYPE_RINGBUF);
        __uint(max_entries, 1 << 24);
} events SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, MAX_ENTRIES);
        __type(key, u32);                       // PID
        __type(value, char[MAX_COMM_LEN]);      // command name
} comms SEC(".maps");                           // proc commands

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, MAX_ENTRIES);
        __type(key, u32);                       // PID
        __type(value, u8[MAX_SYSCALLS]);        // syscall id
} syscalls SEC(".maps");    

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, pid_t);
	__type(value, u32);
} proc_state SEC(".maps");

void __always_inline submit_event(struct task_struct *task, u32 pid, u32 mntns, u32 syscall_id, unsigned char times, unsigned int state)
{
        struct syscall_event *event = bpf_ringbuf_reserve(&events, sizeof(struct syscall_event), 0);
        if (!event) {
                // 没有足够rb空间
                bpf_printk("No enough space for ringbuffer !!");
                return ;
        }

        event->pid = pid;
        event->ppid = BPF_CORE_READ(task, real_parent, tgid);
        event->mntns = mntns;
        event->syscall_id = syscall_id;
        event->occur_times = times;
        event->state = state;
        // event->con_id = con_id;
        bpf_get_current_comm(&event->comm, sizeof(event->comm));

        bpf_ringbuf_submit(event, 0);
}




/* phase1：runc进程开始时 */
SEC("uprobe")
int BPF_UPROBE(start)
{
    int ppid;
    int pid = bpf_get_current_pid_tgid()>>32;
    unsigned int state;

    state = START;
    bpf_printk("fuck! state is : %u", state);
    bpf_map_update_elem(&proc_state, &pid, &state, BPF_ANY);

    void *ptr = bpf_map_lookup_elem(&proc_state, &pid);
    if (!ptr) {
        return 0;
    }
    unsigned int *p = ptr;

    /* Test proc */
    // state = bpf_map_lookup_elem(&proc_state, &pid);
    bpf_printk("Find state start!, state is %u", *p);

    return 0;
}


/* phase2: runc 初始化结束 */
SEC("uprobe")
int BPF_UPROBE(runc_init)//容器进程开始同步，探测阶段2开始
{
    int pid = bpf_get_current_pid_tgid()>>32;
    int state;

    state = INIT;
    bpf_map_update_elem(&proc_state, &pid, &state, BPF_ANY);

    /* Test proc */
    bpf_printk("Find state in init !!");

    return 0;
}

SEC("uprobe")
int BPF_UPROBE(read_fifofd)
{
    int pid = bpf_get_current_pid_tgid()>>32;
    unsigned int state;

    state = FIFO;
    bpf_map_update_elem(&proc_state, &pid, &state, BPF_ANY);

    void *ptr = bpf_map_lookup_elem(&proc_state, &pid);
    if (!ptr) {
        return 0;
    }
    unsigned int *p = ptr;
    /* Test proc */
    bpf_printk("_read fifo! state is : %u", *p);

    return 0;
}



SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	
	u64 pid = bpf_get_current_pid_tgid() >> 32;
	u64 mntns;

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	mntns = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
    int state = 0x0;

	// // 给一个进程标记即可，标记其为容器进程的哪个阶段
    bpf_map_update_elem(&proc_state, &pid, &state, BPF_ANY);
    // bpf_printk("tag proc!!");

    
	return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int sys_enter(struct trace_event_raw_sys_enter *args) 
{
        // id 合理性检查
        u32 pid = bpf_get_current_pid_tgid() >> 32;
        u32 syscall_id = args->id;
        if (syscall_id < 0 || syscall_id >= MAX_SYSCALLS)
                return 0;
        // unsigned int container_id;

        void *ptr = bpf_map_lookup_elem(&proc_state, &pid);
        unsigned int *p = ptr;
        if (!ptr) {
            return 0;
        }
        if (*p <= 0) {
            // bpf_printk("");
            return 0;
        }
        unsigned int state = *p;

        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        u64 mntns = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
        
        u8 *syscall_value = bpf_map_lookup_elem(&syscalls, &pid);
        if (!syscall_value) {
            submit_event(task, pid, mntns, syscall_id, 1, state);
            static unsigned char init[MAX_SYSCALLS];
            init[syscall_id]++;
            bpf_map_update_elem(&syscalls, &pid, &init, BPF_ANY);
            const u8 *value = bpf_map_lookup_elem(&syscalls, &pid);
            if (!value) {
                return 0;
            }
            return 0;
        } else {
            if (syscall_value[syscall_id] == 0) {
                submit_event(task, pid, mntns, syscall_id, 1, state);
                syscall_value[syscall_id] = 1;
                return 0;
            } else {
                syscall_value[syscall_id]++;
                return 0;
            }
        }

        return 0;
}

char LICENSE[] SEC("license") = "GPL";
