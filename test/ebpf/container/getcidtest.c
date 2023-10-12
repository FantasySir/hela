#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "docker.h"

int main(void) {
  char *abpath = "/var/snap/docker/common/var-lib-docker/containers";
  char **containerid_list = (char **)malloc(sizeof(char *) * 5000);
  int i;
  for (i = 0; i < MAX_CONTAINERS; ++i) {
    containerid_list[i] = (char *)malloc(sizeof(char) * 64);
  }
  getContainerid(abpath, containerid_list);

  printf("container1 cid is : %s\n", containerid_list[0]);
  return 0;
}