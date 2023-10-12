#ifndef DOCKER__H
#define DOCKER__H

#define MAX_CONTAINERS 5000

#include "../process/process.h"

struct container_event {
  struct process_event process;
  unsigned long container_id;
  char container_name[100];
};

#endif