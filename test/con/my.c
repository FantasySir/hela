// 文件名: simple_syscalls.c
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

int main() {
    int fd;
    char *text = "Hello, system calls!\\n";

    int i;

    for (i = 0; i < 1000; ++i){
// 打开（或创建）一个文件
    fd = open("example.txt", O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    if (fd == -1) {
        printf("open");
        // return 1;
    }

    sleep(1);

    // 写入文本到文件
    if (write(fd, text, 22) == -1) { // "Hello, system calls!\\n" 长度为22
        printf("write");
        // return 1;
    }

    sleep(1);

    // 关闭文件
    if (close(fd) == -1) {
        printf("close");
        // return 1;
    }
    }

    

    return 0;
}