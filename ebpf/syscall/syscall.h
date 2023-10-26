/*
 Copyright 2023 Broin

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

      https://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 */

#ifndef SYSCALL__H
#define SYSCALL__H

// #include <linux/bpf.h>
#define SYSCALL_TASK_COMM_LEN 64

struct syscall_event
{
        int pid;
        int ppid;
        uint32_t syscall_id;
        uint64_t mntns;
        char comm[SYSCALL_TASK_COMM_LEN];
        unsigned char occur_times;
};


#endif // !SYSCALL__H