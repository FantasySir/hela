#ifndef DOCKER__H
#define DOCKER__H

struct container_event {
	struct process_event process;
	unsigned long container_id;
	char container_name[100];
};

#endif