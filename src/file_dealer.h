#ifndef FILE_DEALER_H
#define FILE_DEALER_H

#include <stdio.h>
#include <stdlib.h>
// #include "hashmap.h"

int out2File(char *in, char *file_path) 
{
	FILE *file = fopen(file_path, "a");
	if (file == NULL) {
		perror("Failed to open or create file!");
		return 0;
	}
	fprintf(file, "%s\n", in);
	fclose(file);
	return 1;
}

int read2map(const char *file_path, HashMap *map)
{
	FILE* file = fopen(file_path, "r");
    	if (file == NULL) {
        	perror("Failed to open file for reading");
        	return 0;
    	}

    	char buffer[65]; // 假设一行不超过66个字符
    	while (fgets(buffer, sizeof(buffer), file)) {
		size_t length = strcspn(buffer, "\n");
		buffer[length] = '\0';
       		 hash_map_insert(map, buffer);
    	}
	fclose(file);
	return 1;
}

#endif