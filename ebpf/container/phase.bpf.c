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
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "phase.h"

struct initConfig {
	char **Args;
	char **Env;
	char *Cwd;
	char **Capabilities;
	char *ProcessLabel;
	char *AppArmorProfile;
	bool NoNewPrivileges;
	char *User;
	char **AdditionalGroups;
	char **Config;
	char **Networks;
	int PassedFilesCount;
	char *ContainerID;
	char **Rlimits;
	bool CreateConsole;
	uint16_t ConsoleWidth;
	uint16_t ConsoleHeight;
	bool RootlessEUID;
	bool RootlessCgroups;
	char *SpecState;
	char *Cgroup2Path;
};
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
int  print_func(struct pt_regs *ctx){
        void *arg1;
        char *arg1_i;
        arg1 = (void *)PT_REGS_PARM1(ctx);
        bpf_probe_read_kernel(&arg1_i,sizeof(arg1_i),(void *)&arg1);
        bpf_printk("arg1 is %s",arg1_i);
        arg1 = (void *)PT_REGS_PARM2(ctx);
        bpf_probe_read_kernel(&arg1_i,sizeof(arg1_i),(void *)&arg1);
        bpf_printk("arg2 is %s",arg1_i);
        arg1 = (void *)PT_REGS_PARM3(ctx);
        bpf_probe_read_kernel(&arg1_i,sizeof(arg1_i),(void *)&arg1);
        bpf_printk("arg3 is %s",arg1_i);
        arg1 = (void *)PT_REGS_PARM4(ctx);
        bpf_probe_read_kernel(&arg1_i,sizeof(arg1_i),(void *)&arg1);
        bpf_printk("arg4 is %s",arg1_i);
        arg1 = (void *)PT_REGS_PARM5(ctx);
        bpf_probe_read_kernel(&arg1_i,sizeof(arg1_i),(void *)&arg1);
        bpf_printk("arg5 is %s",arg1_i);
        arg1 = (void *)PT_REGS_RET(ctx);
        bpf_probe_read_kernel(&arg1_i,sizeof(arg1_i),(void *)&arg1);
        bpf_printk("RET is %s",arg1_i);
        arg1 = (void *)PT_REGS_FP(ctx);
        bpf_probe_read_kernel(&arg1_i,sizeof(arg1_i),(void *)&arg1);
        bpf_printk("FP is %s",arg1_i);
        arg1 = (void *)PT_REGS_RC(ctx);
        bpf_probe_read_kernel(&arg1_i,sizeof(arg1_i),(void *)&arg1);
        bpf_printk("RC is %s",arg1_i);
        arg1 = (void *)PT_REGS_SP(ctx);
        bpf_probe_read_kernel(&arg1_i,sizeof(arg1_i),(void *)&arg1);
        bpf_printk("SP is %s",arg1_i);
        arg1 = (void *)PT_REGS_IP(ctx);
        bpf_probe_read_kernel(&arg1_i,sizeof(arg1_i),(void *)&arg1);
        bpf_printk("IP is %s",arg1_i);
        void *arg2;
        char *arg2_i;
        arg2 = (void *)go_get_argument(ctx,1,1);
        bpf_probe_read_kernel(&arg2_i,sizeof(arg2_i),(void *)&arg2);
        bpf_printk("arg1 is %s",arg2_i);
        arg2 = (void *)go_get_argument(ctx,1,2);
        bpf_probe_read_kernel(&arg2_i,sizeof(arg2_i),(void *)&arg2);
        bpf_printk("arg2 is %s",arg2_i);
        arg2 = (void *)go_get_argument(ctx,1,3);
        bpf_probe_read_kernel(&arg2_i,sizeof(arg2_i),(void *)&arg2);
        bpf_printk("arg3 is %s",arg2_i);
        arg2 = (void *)go_get_argument(ctx,1,4);
        bpf_probe_read_kernel(&arg2_i,sizeof(arg2_i),(void *)&arg2);
        bpf_printk("arg4 is %s",arg2_i);
        arg2 = (void *)go_get_argument(ctx,1,5);
        bpf_probe_read_kernel(&arg2_i,sizeof(arg2_i),(void *)&arg2);
        bpf_printk("arg5 is %s",arg2_i);
        arg2 = (void *)go_get_argument(ctx,1,6);
        bpf_probe_read_kernel(&arg2_i,sizeof(arg2_i),(void *)&arg2);
        bpf_printk("arg6 is %s",arg2_i);
        arg2 = (void *)go_get_argument(ctx,1,7);
        bpf_probe_read_kernel(&arg2_i,sizeof(arg2_i),(void *)&arg2);
        bpf_printk("arg7 is %s",arg2_i);
        arg2 = (void *)go_get_argument(ctx,1,8);
        bpf_probe_read_kernel(&arg2_i,sizeof(arg2_i),(void *)&arg2);
        bpf_printk("arg8 is %s",arg2_i);
        arg2 = (void *)go_get_argument(ctx,1,9);
        bpf_probe_read_kernel(&arg2_i,sizeof(arg2_i),(void *)&arg2);
        bpf_printk("arg9 is %s",arg2_i);
        arg2 = (void *)GOROUTINE(ctx);
        bpf_probe_read_kernel(&arg2_i,sizeof(arg2_i),(void *)&arg2);
        bpf_printk("ROUTINE is %s",arg2_i);
        arg2 = (void *)GO_SP(ctx);
        bpf_probe_read_kernel(&arg2_i,sizeof(arg2_i),(void *)&arg2);
        bpf_printk("SP is %s",arg2_i);
        arg2 = (void *)go_get_argument(ctx,0,1);
        bpf_probe_read_kernel(&arg2_i,sizeof(arg2_i),(void *)&arg2);
        bpf_printk("arg1 is %s",arg2_i);
        arg2 = (void *)go_get_argument(ctx,0,2);
        bpf_probe_read_kernel(&arg2_i,sizeof(arg2_i),(void *)&arg2);
        bpf_printk("arg2 is %s",arg2_i);
        arg2 = (void *)go_get_argument(ctx,0,3);
        bpf_probe_read_kernel(&arg2_i,sizeof(arg2_i),(void *)&arg2);
        bpf_printk("arg3 is %s",arg2_i);
        arg2 = (void *)go_get_argument(ctx,0,4);
        bpf_probe_read_kernel(&arg2_i,sizeof(arg2_i),(void *)&arg2);
        bpf_printk("arg4 is %s",arg2_i);
        arg2 = (void *)go_get_argument(ctx,0,5);
        bpf_probe_read_kernel(&arg2_i,sizeof(arg2_i),(void *)&arg2);
        bpf_printk("arg5 is %s",arg2_i);
        arg2 = (void *)go_get_argument(ctx,0,6);
        bpf_probe_read_kernel(&arg2_i,sizeof(arg2_i),(void *)&arg2);
        bpf_printk("arg6 is %s",arg2_i);
        arg2 = (void *)go_get_argument(ctx,0,7);
        bpf_probe_read_kernel(&arg2_i,sizeof(arg2_i),(void *)&arg2);
        bpf_printk("arg7 is %s",arg2_i);
        arg2 = (void *)go_get_argument(ctx,0,8);
        bpf_probe_read_kernel(&arg2_i,sizeof(arg2_i),(void *)&arg2);
        bpf_printk("arg8 is %s",arg2_i);
        arg2 = (void *)go_get_argument(ctx,0,9);
        bpf_probe_read_kernel(&arg2_i,sizeof(arg2_i),(void *)&arg2);
        bpf_printk("arg9 is %s",arg2_i);
    return 0;
}
struct {
    __uint(type,BPF_MAP_TYPE_HASH);
    __uint(max_entries,1000);
    __type(key,pid_t);
    __type(value,struct container_process);
} Docker_ID SEC(".maps");
SEC("uretprobe//bin/bash:readline")
int BPF_KRETPROBE(printret, const void *ret)
{
 char str[MAX_LINE_SIZE];
 char comm[TASK_COMM_LEN];
 u32 pid;

 if (!ret)
  return 0;

 bpf_get_current_comm(&comm, sizeof(comm));

 pid = bpf_get_current_pid_tgid() >> 32;
 bpf_probe_read_user_str(str, sizeof(str), ret);

 bpf_printk("PID %d (%s) read: %s ", pid, comm, str);

 return 0;
};
//测试
/*SEC("uprobe")
int BPF_UPROBE(main_phase1)
{
    bpf_printk("phase1!");
    return 0;
}
SEC("uprobe//home/lsh/uprobe-container/test:main.main")
int BPF_UPROBE(main_main)
{
    bpf_printk("main1!");
    return 0;
}
*/
//gRPC从daemon到containerd
SEC("kprobe/__x64_sys_execve")
int BPF_KPROBE(Exec_containerd)
{
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm)); 
    if(bpf_strncmp(comm,10,"containerd")==0){
        int pid = bpf_get_current_pid_tgid()>>32;
        bpf_printk("cmd is %s, Pid is %d!",comm,pid);
    }
    return 0;
}
//执行命令从containerd到runc:docker-containerd-shim ID bundle docker-runc
SEC("kprobe/__x64_sys_execve")
int BPF_KPROBE(Exec_shim)
{
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm)); 
    if(bpf_strncmp(comm,15,"containerd-shim")==0){
        int pid = bpf_get_current_pid_tgid()>>32;
        bpf_printk("cmd is %s, Pid is %d!",comm,pid);
    }
    return 0;
}
//runc阶段的开始执行命令:docker-runc create --bundle --console --pid-file
SEC("kprobe/__x64_sys_execve")
int BPF_KPROBE(Exec_runc)
{
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm)); 
    if(bpf_strncmp(comm,4,"runc")==0){
        int pid = bpf_get_current_pid_tgid()>>32;
        struct task_struct *task;
        task = (struct task_struct *)bpf_get_current_task();
        int ppid = BPF_CORE_READ(task, real_parent, tgid);
        bpf_printk("cmd is %s, Pid is %d,PPid is %d!",comm,pid,ppid);
    }
    return 0;
}
//测试
/*SEC("uprobe//home/lsh/uprobe-container/test:main.phase1")
int BPF_UPROBE(test)
{
    void *arg1;
    int32_t arg1_i;
    arg1 = (void *)go_get_argument(ctx,1,1);
    bpf_probe_read_kernel(&arg1_i,sizeof(arg1_i),(void *)&arg1);
    bpf_printk("arg1 is %d",arg1_i);
    return 0;
}*/


//runc/libcontainer/factory_linux.go下libcontainer.Create方法创建容器对象，第二个参数是容器ID
SEC("uprobe")
int BPF_UPROBE(container_create)
{
    int pid = bpf_get_current_pid_tgid()>>32;
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
    bpf_printk("container_Create start! Pid is %d,cmd is %s!",pid,comm);
    
    //print_func(ctx);
    void *arg2;
    char *arg2_i;
    arg2 = (void *)go_get_argument(ctx,1,3);
    bpf_probe_read_kernel(&arg2_i,sizeof(arg2_i),(void *)&arg2);
    //先存容器ID,之后进入容器再存容器进程id
    struct container_process cp1={0};
    bpf_probe_read_str(&cp1.cid, sizeof(cp1.cid),arg2_i);
    bpf_map_update_elem(&Docker_ID,&pid,&cp1,BPF_ANY);

    bpf_printk("arg2 is %s",arg2_i);
    return 0;
}
//CreateLibcontainerConfig下配置容器，/home/lsh/uprobe-container/runc/libcontainer/specconv/spec_linux.go下
SEC("uprobe")
int BPF_UPROBE(container_config)
{
    pid_t pid;
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
    pid = bpf_get_current_pid_tgid()>>32;
    bpf_printk("CreateLibcontainerConfig! Pid is %d,cmd is %s!",pid,comm);
    void *arg;
    char *rootfs;
    arg = (void *)go_get_argument(ctx,1,1);
    bpf_probe_read_kernel(&rootfs,sizeof(rootfs),(void *)&arg);
    bpf_printk("rootfs is %s",rootfs);

    return 0;
}
//bootstrap下nsexec方法开始设置namespace //home/lsh/uprobe-container/runc/runc:libcontainer.start
SEC("uprobe")
int BPF_UPROBE(bootstrap1)
{
    pid_t pid;
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
    pid = bpf_get_current_pid_tgid()>>32;
    bpf_printk("runc's bootstrap start! Pid is %d,cmd is %s!",pid,comm);
    
    return 0;
}
//runc init进程接收同步消息后开始初始化cgroup,seccomp libcontainer.(*linuxStandardInit).Init
//libcontainer/standard_init_linux.go的linuxStandardInit下:
SEC("uprobe")
int BPF_UPROBE(runc_init)
{
    pid_t pid;
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
    pid = bpf_get_current_pid_tgid()>>32;
    bpf_printk("runc's standard init start! Pid is %d,cmd is %s!",pid,comm);
    
    return 0;
}
//containerInit函数搜集容器的全部config，用于容器进程的创建
SEC("uprobe")
int BPF_UPROBE(runc_containerInit)
{
    pid_t pid;
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
    pid = bpf_get_current_pid_tgid()>>32;
    bpf_printk("runc's containerInit start! Pid is %d,cmd is %s!",pid,comm);
    
    return 0;
}

//容器初始化完成之后阻塞exec的fifo管道代表等待容器启动命令 
//libcontainer/standard_init_linux.go的linuxStandardInit下:
/*SEC("kprobe/__x64_sys_close")
int BPF_KPROBE(Close_fifofd)
{
    pid_t pid;
    pid = bpf_get_current_pid_tgid() >> 32;
    struct container_process *tsp;
    tsp = bpf_map_lookup_elem(&Docker_ID,&pid);
    if(tsp!=NULL){
        char comm[TASK_COMM_LEN];
        bpf_get_current_comm(&comm, sizeof(comm));
        bpf_printk("Standard init close the fifo fd! Pid is %d,cmd is %s!",pid,comm);
    }
    return 0;
}*/
//readFromExecFifo读取管道数据，解除阻塞，查看返回值是否为空，若不为空则有错误。
//runc/libcontainer/container_linux.go下：
SEC("uprobe")
int BPF_UPROBE(read_fifofd)
{
    void *ret;
    ret = (void *)go_get_argument(ctx,1,1);
    char *ret1;
    bpf_probe_read_kernel(&ret1,sizeof(ret1),(void *)&ret);
    bpf_printk("ret = %x,ret1 = %s",ret,ret1);
    if(ret==NULL){
        pid_t pid;
        pid = bpf_get_current_pid_tgid() >> 32;
        char comm[TASK_COMM_LEN];
        bpf_get_current_comm(&comm, sizeof(comm));
        bpf_printk("exec read from fifo fd with no error! Pid is %d,cmd is %s!",pid,comm);
    }
    return 0;
}

//exec程序打开exec fifo并执行exec系统调用启动容器.
/*SEC("kprobe/__x64_sys_execve")
int BPF_KPROBE(Exec)
{
    unsigned fname_off;
    char comm[TASK_COMM_LEN];
    char filename[MAX_FILENAME_LEN];
    bpf_get_current_comm(&comm, sizeof(comm)); 
    if(bpf_strncmp(comm,1,"6")==0){ 
        int pid = bpf_get_current_pid_tgid()>>32;
        bpf_printk("runc's Exec start! Pid is %d",pid);
        bpf_printk("cmd is %s",comm);
        fname_off = ctx->__data_loc_filename & 0xFFFF;
	    bpf_probe_read_str(&filename, sizeof(filename), (void *)ctx + fname_off);
        bpf_printk("filename is %s",filename);
    }
    return 0;
}*/
//tracepoint跟踪exec进入容器进程
SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    pid_t pid,ppid;
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
    //bpf_printk("cmd is %s",comm);
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
	return 0;
}


char LICENSE[] SEC("license") = "GPL";
