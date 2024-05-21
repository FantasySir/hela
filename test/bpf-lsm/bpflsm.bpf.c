#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <linux/lsm_hooks.h>
#include <linux/fs.h>

const volatile char target_path[] = "/root/text.txt";

SEC("lsm/file_permission")
int BPF_PROG(check_file_write_permission, struct file *file, int mask)
{
    // 只关心写操作
    if (!(mask & (MAY_WRITE | MAY_APPEND)))
        return 0;

    char buf[256] = {};
    long ret;

    // 获取文件路径
    ret = bpf_d_path(&file->f_path, buf, sizeof(buf));
    if (ret < 0)
        return 0;

    // 检查文件路径是否为我们想要保护的路径
    if (bpf_strncmp(buf, target_path, sizeof(target_path)) == 0) {
        // 阻止对特定文件的写入
        return -EPERM;
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";