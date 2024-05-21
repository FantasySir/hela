// SPDX-License-Identifier: GPL-2.0
#include <assert.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <linux/bpf.h>
#include <linux/seccomp.h>
#include <linux/unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <stdint.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <bpf/bpf.h>
#include <sys/wait.h>
#include <jansson.h>
#include "seccomp.skel.h"
#include "seccomp.h"
#define CON_PIN_PATH              "/sys/fs/bpf/con_phase"
#define warn(...) fprintf(stderr, __VA_ARGS__)

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
			   va_list args)
{
	return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	int err;
	const struct containerd_rootfs *e = data;
	struct seccomp_bpf *skel = (struct seccomp_bpf *)ctx;
	printf(" Pid: %d\n", e->number);
	printf("rootfs Path: %s\n", e->rootfs);
    // 打开 JSON 文件
	char json_path[120] = {0};
	strcpy(json_path,e->rootfs);
	strcat(json_path,"/config.json");
	printf("json_path: %s\n", json_path);
    FILE *file = fopen(json_path, "r");
    if (!file) {
        fprintf(stderr, "Error opening JSON file\n");
        return 1;
    }

    // 读取 JSON 文件内容
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    char *json_data = (char *)malloc(file_size + 1);
    fread(json_data, 1, file_size, file);
    fclose(file);

    // 添加字符串结束符
    json_data[file_size] = '\0';

    // 解析 JSON 数据
    json_t *root;
    json_error_t error;
    root = json_loads(json_data, 0, &error);

    // 检查是否成功解析
    if (!root) {
        fprintf(stderr, "Error parsing JSON: %s\n", error.text);
        free(json_data);
        return 1;
    }

    // 获取 root 下的 path 字符串
    json_t *root_obj = json_object_get(root, "root");
    json_t *path_obj = json_object_get(root_obj, "path");
    const char *root_path = json_string_value(path_obj);

    // 打印结果
    printf("Root Path: %s\n", root_path);
	char nginx_path[150] = {0};
	strcpy(nginx_path,root_path);
	strcat(nginx_path,"/usr/sbin/nginx");

	printf("nginx Path: %s\n", nginx_path);
	skel->links.ngx_spawn_process_cycle = bpf_program__attach_uprobe(skel->progs.ngx_spawn_process_cycle,
		false,-1,nginx_path,0x51c90);
	err = libbpf_get_error(skel->links.ngx_spawn_process_cycle);
	if (err) {
		fprintf(stderr, "Failed to attach uprobe!\n");
		// goto cleanup;
	}
    // 释放内存
    free(json_data);
    json_decref(root);

	return 0;
}
int main(int argc, char **argv)
{

    struct seccomp_bpf *skel;
	struct ring_buffer *rb = NULL;
	int err;
	//char *runc_path = "/home/lsh/uprobe-container/containers/mycontainer1/runc";
	char *runc_sys = "/usr/local/sbin/runc_real";
	libbpf_set_print(libbpf_print_fn);

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Load and verify BPF application */
	skel = seccomp_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Load & verify BPF programs */
	err = seccomp_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		perror("load error");
	}

	err = bpf_map__pin(skel->maps.phase, CON_PIN_PATH);
    if (err) {
        fprintf(stderr, "Failed to pin shared map \n");
		perror("pin error");
    }

	err = seccomp_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}
	skel->links.start = bpf_program__attach_uprobe(skel->progs.start,
	false,-1,runc_sys,0x159600);
	err = libbpf_get_error(skel->links.start);
	if (err) {
		fprintf(stderr, "Failed to attach uprobe!\n");
		goto cleanup;
	}
	skel->links.container_create = bpf_program__attach_uprobe(skel->progs.container_create,
	false,-1,runc_sys,0x42dce0);
	err = libbpf_get_error(skel->links.container_create);
	if (err) {
		fprintf(stderr, "Failed to attach uprobe!\n");
		goto cleanup;
	}
	skel->links.bootstrap1 = bpf_program__attach_uprobe(skel->progs.bootstrap1,
	false,-1,runc_sys,0x436780);
	err = libbpf_get_error(skel->links.bootstrap1);
	if (err) {
		fprintf(stderr, "Failed to attach uprobe!\n");
		goto cleanup;
	}
	skel->links.runc_init = bpf_program__attach_uprobe(skel->progs.runc_init,
	false,-1,runc_sys,0x442520);
	err = libbpf_get_error(skel->links.runc_init);
	if (err) {
		fprintf(stderr, "Failed to attach uprobe!\n");
		goto cleanup;
	}
	// skel->links.runc_containerInit = bpf_program__attach_uprobe(skel->progs.runc_containerInit,
	// false,-1,runc_sys,0x42fb40);
	// err = libbpf_get_error(skel->links.runc_containerInit);
	// if (err) {
	// 	fprintf(stderr, "Failed to attach uprobe!\n");
	// 	goto cleanup;
	// }
	skel->links.read_fifofd = bpf_program__attach_uprobe(skel->progs.read_fifofd,
	false,-1,runc_sys,0x41df05);
	err = libbpf_get_error(skel->links.read_fifofd);
	if (err) {
		fprintf(stderr, "Failed to attach uprobe!\n");
		goto cleanup;
	}
	skel->links.container_config = bpf_program__attach_uprobe(skel->progs.container_config,
	false,-1,runc_sys,0x4a6f96);
	err = libbpf_get_error(skel->links.container_config);
	if (err) {
		fprintf(stderr, "Failed to attach uprobe!\n");
		goto cleanup;
	}
	skel->links.join_namespaces = bpf_program__attach_uprobe(skel->progs.join_namespaces,
	false,-1,runc_sys,0x4f1710);
	err = libbpf_get_error(skel->links.join_namespaces);
	if (err) {
		fprintf(stderr, "Failed to attach uprobe!\n");
		goto cleanup;
	}
		
	rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, skel, NULL);
	if (!rb) {
		err = -1;
		goto cleanup;
	}
	
	while(!exiting){
		err=ring_buffer__poll(rb,100);
		if (err == -EINTR) {
		err = 0;
		break;
		}
		if (err < 0) {
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
	}

	while (!exiting) {
		sleep(1);
	}


cleanup:
	ring_buffer__free(rb);
	if (skel) {
        bpf_map__unpin(skel->maps.phase, CON_PIN_PATH);
    }
	seccomp_bpf__destroy(skel);
	return err < 0 ? -err : 0;
	// return 0;
}