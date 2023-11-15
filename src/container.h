#ifndef CONTAINER__H
#define CONTAINER__H

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <argp.h>
#include <time.h>
#include <sys/resource.h>
// #include <bpf/libbpf.h>
// #include <bpf/bpf.h>

#include "../ebpf/common.h"
#include "../ebpf/process/process.h"
#include "../ebpf/process/.output/process.skel.h"
#include "../ebpf/syscall/syscall.h"
#include "../ebpf/syscall/.output/syscall.skel.h"
#include "../ebpf/container/phase.h"
#include "../ebpf/container/.output/phase.skel.h"

int start_trackers(char *output_path, int exiting);


#endif // !CONTAINER__H
