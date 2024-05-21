#include <unistd.h>
#include <sys/syscall.h>
#include <string.h>

int main() {
    const char message[] = "Hello, syscall()!\\n";
    // 使用 syscall 函数进行系统调用
    // SYS_write 是 write 系统调用的编号
    // STDOUT_FILENO 是标准输出的文件描述符
    // message 是要写入的数据的指针
    // strlen(message) 是要写入的字节数
    syscall(SYS_write, STDOUT_FILENO, message, strlen(message));
    return 0;
}