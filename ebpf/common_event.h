#ifndef COMMON_EVENT__H
#define COMMON_EVENT__H

struct common_event {
	int pid;
	int ppid;
	uint64_t cgroup_id;
	uint32_t user_namespace_id;
	uint32_t pid_namespace_id;
	uint64_t mount_namespace_id;
};

#endif // !COMMON_EVENT__H
