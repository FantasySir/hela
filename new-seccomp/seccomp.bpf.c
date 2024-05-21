// SPDX-License-Identifier: GPL-2.0
#define BPF_NO_GLOBAL_DATA
#define GO_PARAM1(x) BPF_CORE_READ((x), ax)
#define GO_PARAM2(x) BPF_CORE_READ((x), bx)
#define GO_PARAM3(x) BPF_CORE_READ((x), cx)
#define GO_PARAM4(x) BPF_CORE_READ((x), di)
#define GO_PARAM5(x) BPF_CORE_READ((x), si)
#define GO_PARAM6(x) BPF_CORE_READ((x), r8)
#define GO_PARAM7(x) BPF_CORE_READ((x), r9)
#define GO_PARAM8(x) BPF_CORE_READ((x), r10)
#define GO_PARAM9(x) BPF_CORE_READ((x), r11)
#define GOROUTINE(x) BPF_CORE_READ((x), r14)
#define GO_SP(x) BPF_CORE_READ((x), sp)
#include <vmlinux.h>
// #include <linux/seccomp.h>
// #include <linux/bpf.h>
#include <linux/unistd.h>
#include <linux/errno.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
// #include <linux/audit.h>
// #include <linux/sched.h>

#include "seccomp.h"
#define SECCOMP_RET_ALLOW	 0x7fff0000U
void* go_get_argument_by_reg(struct pt_regs *ctx, int index) {
    switch (index) {
        case 1:
            return (void*)GO_PARAM1(ctx);
        case 2:
            return (void*)GO_PARAM2(ctx);
        case 3:
            return (void*)GO_PARAM3(ctx);
        case 4:
            return (void*)GO_PARAM4(ctx);
        case 5:
            return (void*)GO_PARAM5(ctx);
        case 6:
            return (void*)GO_PARAM6(ctx);
        case 7:
            return (void*)GO_PARAM7(ctx);
        case 8:
            return (void*)GO_PARAM8(ctx);
        case 9:
            return (void*)GO_PARAM9(ctx);
        default:
            return NULL;
    }
}
void* go_get_argument_by_stack(struct pt_regs *ctx, int index) {
    void* ptr = 0;
    bpf_probe_read(&ptr, sizeof(ptr), (void *)(PT_REGS_SP(ctx)+(index*8)));
    return ptr;
}

void* go_get_argument(struct pt_regs *ctx,bool is_register_abi, int index) {
    if (is_register_abi) {
        return go_get_argument_by_reg(ctx, index);
    }
    return go_get_argument_by_stack(ctx, index);
}
struct {
    __uint(type,BPF_MAP_TYPE_HASH);
    __uint(max_entries,1000);
    __type(key,pid_t);
    __type(value,struct container_process);
} Docker_ID SEC(".maps");

struct {
    __uint(type,BPF_MAP_TYPE_HASH);
    __uint(max_entries,1000);
    __type(key,pid_t);
    __type(value,struct shim_process);
} Shim SEC(".maps");

struct {
    __uint(type,BPF_MAP_TYPE_HASH);
    __uint(max_entries,10);
    __type(key,int);
    __type(value,int);
} phase SEC(".maps");

struct {
    __uint(type,BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries,256*1024);
} events SEC(".maps");


// 执行命令从containerd到runc:docker-containerd-shim ID bundle docker-runc
// SEC("kprobe/__x64_sys_execve")
// int BPF_KPROBE(Exec_shim)
// {
//     char comm[TASK_COMM_LEN];
//     bpf_get_current_comm(&comm, sizeof(comm)); 
//     if(bpf_strncmp(comm,15,"containerd-shim")==0){
//         struct task_struct *task;
//         task = (struct task_struct *)bpf_get_current_task();
//         int ppid = BPF_CORE_READ(task, real_parent, tgid);
//         int pid = bpf_get_current_pid_tgid()>>32;
//         struct shim_process *sp;
//         sp = bpf_map_lookup_elem(&Shim,&ppid);
//         if(sp==NULL){//shim1未注册
//             bpf_printk("shim1!");
//             struct shim_process sp1={0};
//             sp1.ppid = pid;
//             bpf_map_update_elem(&Shim,&pid,&sp1,BPF_ANY);//将shim1的pid当作键值存入
//             bpf_printk("%s-1, Pid is %d,PPid is %d!",comm,pid,ppid);
//         }
//         else if(sp!=NULL){//shim1已注册,注册shim2,探测阶段1开始
//             int p=1,app=1;
//             bpf_map_update_elem(&phase,&app,&p,BPF_ANY);
//             bpf_printk("shim2!");
//             sp->pid = pid;
//             //bpf_probe_read_str(&sp.pid, sizeof(sp.pid),pid);
//             bpf_map_update_elem(&Shim,&ppid,&sp,BPF_ANY);
//             bpf_printk("%s-2, Pid is %d,PPid is %d!",comm,pid,ppid);
//         }
        
//     }
//     return 0;
// }
SEC("uprobe")
int BPF_UPROBE(start)
{
    int ppid;
    int pid = bpf_get_current_pid_tgid()>>32;
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    ppid = BPF_CORE_READ(task, real_parent, tgid);
    bpf_printk("_start! Pid is %d,PPid is %d,cmd is %s!",pid,ppid,comm);
    return 0;
}
SEC("uprobe")
int BPF_UPROBE(container_create)
{
    int ppid;
    int pid = bpf_get_current_pid_tgid()>>32;
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    ppid = BPF_CORE_READ(task, real_parent, tgid);
    bpf_printk("Get container ID! Pid is %d,PPid is %d,cmd is %s!",pid,ppid,comm);
    
    //print_func(ctx);
    void *arg2;
    char *arg2_i;
    arg2 = (void *)go_get_argument(ctx,1,2);
    bpf_probe_read_kernel(&arg2_i,sizeof(arg2_i),(void *)&arg2);
    //先存容器ID,之后进入容器再存容器进程id
    struct container_process cp1={0};
    bpf_probe_read_str(&cp1.cid, sizeof(cp1.cid),arg2_i);
    bpf_map_update_elem(&Docker_ID,&ppid,&cp1,BPF_ANY);

    bpf_printk("arg2 containerID is %s",arg2_i);
    return 0;
}
//<github.com/opencontainers/runc/libcontainer/specconv.CreateLibcontainerConfig> 1.1.8
//CreateLibcontainerConfig下配置容器，/home/lsh/uprobe-container/runc/libcontainer/specconv/spec_linux.go下
SEC("uprobe")
int BPF_UPROBE(container_config)
{
    pid_t pid,ppid;
    char comm[TASK_COMM_LEN];
    struct containerd_rootfs *event;

    event = bpf_ringbuf_reserve(&events,sizeof(*event),0);
    if(!event)
        return 1;

    bpf_get_current_comm(&comm, sizeof(comm));
    pid = bpf_get_current_pid_tgid()>>32;
    bpf_get_current_comm(&comm, sizeof(comm));
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    ppid = BPF_CORE_READ(task, real_parent, tgid);
    bpf_printk("Get rootfs! Pid is %d,PPid is %d,cmd is %s!",pid,ppid,comm); 
    //print_func(ctx);
    void *arg;
    char *rootfs;
    arg = (void *)go_get_argument(ctx,1,1);
    bpf_probe_read_kernel(&rootfs,sizeof(rootfs),(void *)&arg);
    bpf_printk("rootfs is %s",rootfs);
    bpf_probe_read_str(&event->rootfs, sizeof(event->rootfs),rootfs);
    
    event->number = pid;
    bpf_ringbuf_submit(event, 0);
    return 0;
}
//<github.com/opencontainers/runc/libcontainer.(*initProcess).start> 1.1.8
// runc/libcontainer/process_linux.go下 bootstrap nsexec方法开始设置namespace //home/lsh/uprobe-container/runc/runc:libcontainer.start
SEC("uprobe")
int BPF_UPROBE(bootstrap1)
{
    pid_t pid,ppid;
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
    pid = bpf_get_current_pid_tgid()>>32;
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    ppid = BPF_CORE_READ(task, real_parent, tgid);
    bpf_printk("Bootstrap! Pid is %d,PPid is %d,cmd is %s!",pid,ppid,comm);
    
    return 0;
}
//<github.com/opencontainers/runc/libcontainer.(*linuxStandardInit).Init> 1.1.8
//runc init进程接收同步消息后开始初始化cgroup,seccomp libcontainer.(*linuxStandardInit).Init
//libcontainer/standard_init_linux.go的linuxStandardInit下:
SEC("uprobe")
int BPF_UPROBE(runc_init)//容器进程开始同步，探测阶段2开始
{
    pid_t pid,ppid;
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
    pid = bpf_get_current_pid_tgid()>>32;
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    ppid = BPF_CORE_READ(task, real_parent, tgid);
    bpf_printk("sync! runc's standard init start! Pid is %d,PPid is %d,cmd is %s!",pid,ppid,comm);
    int p=2,app=1;
    bpf_map_update_elem(&phase,&app,&p,BPF_ANY);
    return 0;
}
//4438aa,system.Exec(name, l.config.Args[0:], os.Environ()),容器进程完成同步并且激活，exec进入容器进程。探测阶段3的开始。探测阶段1和2的结束。
SEC("uprobe")
int BPF_UPROBE(runc_containerInit)
{
    pid_t pid,ppid;
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
    pid = bpf_get_current_pid_tgid()>>32;
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    ppid = BPF_CORE_READ(task, real_parent, tgid);
    bpf_printk("runc's containerInit start! Pid is %d,PPid is %d,cmd is %s!",pid,ppid,comm);
    
    return 0;
}

//<github.com/opencontainers/runc/libcontainer.handleFifoResult> 1.1.8
//readFromExecFifo()读取管道数据，解除阻塞，查看返回值是否为空，若不为空则有错误。此插桩点紧随该函数之后
//runc/libcontainer/container_linux.go下：
SEC("uprobe")
int BPF_UPROBE(read_fifofd)
{
    void *ret;
    ret = (void *)go_get_argument(ctx,1,1);
    char *ret1;
    bpf_probe_read_kernel(&ret1,sizeof(ret1),(void *)&ret);
    bpf_printk("readFromExecFifo finish! ret = %x,ret1 = %s",ret,ret1);
    int p=3,app=1;
    bpf_map_update_elem(&phase,&app,&p,BPF_ANY);
    if(ret==NULL){
        pid_t pid;
        pid = bpf_get_current_pid_tgid() >> 32;
        char comm[TASK_COMM_LEN];
        bpf_get_current_comm(&comm, sizeof(comm));
        bpf_printk("exec read from fifo fd with no error! Pid is %d,cmd is %s!",pid,comm);
    }
    return 0;
}
//nsexec.c方法开始调用setns来设置命名空间，libcontainer/nsenter/nsexec.c下join_namespaces函数
SEC("uprobe")
int BPF_UPROBE(join_namespaces)
{
    pid_t pid,ppid;
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
    pid = bpf_get_current_pid_tgid()>>32;
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    ppid = BPF_CORE_READ(task, real_parent, tgid);
    //bpf_printk("setns start! Pid is %d,PPid is %d,cmd is %s!",pid,ppid,comm);
    
    return 0;
}
//nginx应用主循环插桩点:ngx_master_process_cycle
SEC("uprobe")
int BPF_UPROBE(ngx_spawn_process_cycle)
{
    pid_t pid,ppid;
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
    pid = bpf_get_current_pid_tgid()>>32;
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    ppid = BPF_CORE_READ(task, real_parent, tgid);
    bpf_printk("ngx_master_process_cycle start! Pid is %d,PPid is %d,cmd is %s!",pid,ppid,comm);
    
    return 0;
}

//tracepoint跟踪exec进入容器进程
SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    pid_t pid,ppid;
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
    // bpf_printk("cmd is %s,pid is %d.",comm,bpf_get_current_pid_tgid() >> 32);
    if(bpf_strncmp(comm,2,"sh")==0){
        struct task_struct *task;
        task = (struct task_struct *)bpf_get_current_task();
        ppid = BPF_CORE_READ(task, real_parent, tgid);
        struct container_process *cp1;
        cp1 = bpf_map_lookup_elem(&Docker_ID,&ppid);
        if(cp1!=NULL){
            unsigned fname_off;
            char filename[MAX_FILENAME_LEN];
            pid = bpf_get_current_pid_tgid() >> 32;
            bpf_printk("runc's Exec start! Pid is %d",pid);
            bpf_get_current_comm(comm, sizeof(comm));
            cp1->pid = pid;
            cp1->ppid = ppid;
            bpf_map_update_elem(&Docker_ID,&ppid,cp1,BPF_ANY);
            fname_off = ctx->__data_loc_filename & 0xFFFF;
            bpf_probe_read_str(&filename, sizeof(filename), (void *)ctx + fname_off);
            bpf_printk("pid is %d,parent is %d,filename is %s.",pid,ppid,filename);
            bpf_printk("containerID is %s.",cp1->cid);
            
        }
    }
    else if(bpf_strncmp(comm,4,"runc")==0){
        struct task_struct *task;
        task = (struct task_struct *)bpf_get_current_task();
        ppid = BPF_CORE_READ(task, real_parent, tgid);
        bpf_get_current_comm(comm, sizeof(comm));
        pid = bpf_get_current_pid_tgid() >> 32;
        // bpf_printk("runc process! Pid is %d,PPid is %d,cmd is %s!",pid,ppid,comm);
        // if(comm[1]!='\0')
        //     bpf_printk("Found flag: %s\n", comm[1]);
        // if(comm[2]!='\0')
        //     bpf_printk("Found flag: %s\n", comm[2]);
    }
	return 0;
}
SEC("tp/sched/sched_process_exec")
int handle_exec1(struct trace_event_raw_sched_process_exec *ctx)
{
    pid_t pid,ppid;
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
    //bpf_printk("cmd is %s",comm);
    if(bpf_strncmp(comm,4,"bash")==0){
        struct task_struct *task;
        task = (struct task_struct *)bpf_get_current_task();
        ppid = BPF_CORE_READ(task, real_parent, tgid);
        struct container_process *cp1;
        cp1 = bpf_map_lookup_elem(&Docker_ID,&ppid);
        if(cp1!=NULL){
            unsigned fname_off;
            char filename[MAX_FILENAME_LEN];
            pid = bpf_get_current_pid_tgid() >> 32;
            bpf_printk("runc's Exec start! Pid is %d",pid);
            bpf_get_current_comm(comm, sizeof(comm));
            cp1->pid = pid;
            cp1->ppid = ppid;
            bpf_map_update_elem(&Docker_ID,&ppid,cp1,BPF_ANY);
            fname_off = ctx->__data_loc_filename & 0xFFFF;
            bpf_probe_read_str(&filename, sizeof(filename), (void *)ctx + fname_off);
            bpf_printk("pid is %d,parent is %d,filename is %s.",pid,ppid,filename);
            bpf_printk("containerID is %s.",cp1->cid);
            
        }
    }
    else if(bpf_strncmp(comm,6,"docker")==0){
        struct task_struct *task;
        task = (struct task_struct *)bpf_get_current_task();
        ppid = BPF_CORE_READ(task, real_parent, tgid);
        pid = bpf_get_current_pid_tgid() >> 32;
        // bpf_printk("comm is %s,pid is %d,parent is %d.",comm,pid,ppid);
    }
	return 0;
}


char _license[] SEC("license") = "GPL";