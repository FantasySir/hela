#include <bpf/libbpf.h>
#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link;
    char filename[] = "lsm_file_write_control.bpf.o";

    // 初始化libbpf环境
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_print_fn);

    // 加载eBPF程序
    obj = bpf_object__open_file(filename, NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Error opening BPF object: %s\\n", strerror(libbpf_get_error(obj)));
        return 1;
    }

    // 加载和验证BPF程序
    if (bpf_object__load(obj)) {
        fprintf(stderr, "Error loading BPF object\\n");
        return 1;
    }

    // 获取eBPF程序
    prog = bpf_object__find_program_by_title(obj, "lsm/file_permission");
    if (!prog) {
        fprintf(stderr, "Failed to find BPF program\\n");
        return 1;
    }

    // 附加eBPF程序到LSM钩子
    link = bpf_program__attach_lsm(prog);
    if (libbpf_get_error(link)) {
        fprintf(stderr, "Error attaching BPF program to LSM: %s\\n", strerror(libbpf_get_error(link)));
        return 1;
    }

    printf("BPF LSM program loaded and attached. Press ENTER to exit...\\n");
    getchar();

    // 清理资源
    bpf_link__destroy(link);
    bpf_object__close(obj);

    return 0;
}