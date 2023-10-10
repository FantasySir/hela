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

#ifndef PROCESS__H
#define PROCESS__H

#define TASK_COMM_LEN	 16
#define MAX_FILENAME_LEN 127
#define CONTAINER_ID_LEN 127

struct common_event {
	int pid;
	int ppid;
	uint64_t cgroup_id;
	uint32_t user_namespace_id;
	uint32_t pid_namespace_id;
	uint32_t mount_namespace_id;
};

struct process_event {
	struct common_event common;

	unsigned exit_code;
	int pid;
	unsigned long long duration_ns;
	char comm[TASK_COMM_LEN];
	char filename[MAX_FILENAME_LEN];
	int exit_event;
};

#endif // !PROCESS__H