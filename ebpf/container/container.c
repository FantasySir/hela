/*
 Copyright (c) 2023 Broin All rights reserved.
 Use of this source code is governed by a BSD-style
 license that can be found in the LICENSE file.
 */

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <bpf/libbpf.h>

#include "../common.h"
#include "../process/process_tracker.h"


/*
 * TODO:
 * 1. 获取contianer id
 * ./var/snap/docker/common/var-lib-docker/containers
 * 2. 存入map
 */


/**
 * @description: 获取容器id
 * @param {char} *ab_path 容器绝对路径
 * @param {char} **container_list container id列表
 * @return {*}
 */
int getContainerid(char *ab_path, char **container_list) {
  int i;
  DIR *dir;
  struct dirent *cid;

  // init
  dir = opendir(ab_path);
  if (!dir) {
    error("Cannot open direction: %s\n", ab_path);
    return FAIL;
  }
  i = 0;

  // get cid
  while ((cid = readdir(dir)) != NULL) {
    if (!strcmp(cid->d_name, ".") || !strcmp(cid->d_name, ".."))
      continue;
    container_list[i] = cid->d_name;
    ++i;
  }

  return SUCCESS;
}

int loadContainerid() {
  ring_buffer__new(int map_fd, ring_buffer_sample_fn sample_cb, void *ctx, const struct ring_buffer_opts *opts)
    }