#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>


int main() {
	const char *path = "./bb";
	const char *r_path = "./syscall.c";
	char buffer[1024];

	int r_fd = open(r_path, O_RDONLY);
    if (r_fd == -1) {
        perror("open");
        exit(EXIT_FAILURE);
    }
    int fd = open(path, O_RDONLY);
    if (fd == -1) {
        perror("open");
        exit(EXIT_FAILURE);
    }

    ssize_t bytesRead = read(fd, buffer, sizeof(buffer) - 1);
    if (bytesRead == -1) {
        perror("read"); // 读取过程中出错
        close(fd);
        exit(EXIT_FAILURE);
    }

    // 关闭文件
    if (close(fd) == -1) {
        perror("close");
        exit(EXIT_FAILURE);
    }

    return 0;
}