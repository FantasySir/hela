#define _GNU_SOURCE
#include <sched.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <stdio.h>

// 定义栈大小
#define STACK_SIZE (1024 * 1024)

// 子进程将执行的函数
int childFunc(void *arg) {
    printf("Inside new PID namespace\\n");
    // 使用/bin/bash来测试PID命名空间的效果
    char *args[] = { "/bin/bash", NULL };
    execv(args[0], args);
    // 如果execv返回，说明发生了错误
    perror("execv");
    return 1; // 如果到达这里，说明execv调用失败
}

int main() {
    // 为子进程分配栈空间
    char *stack = malloc(STACK_SIZE);
    if (stack == NULL) {
        perror("malloc");
        exit(1);
    }
    char *stackTop = stack + STACK_SIZE;  // 栈顶，因为栈是向下增长的

    // 创建新的PID命名空间的子进程
    pid_t pid = clone(childFunc, stackTop, CLONE_NEWPID | SIGCHLD, NULL);
    if (pid == -1) {
        perror("clone");
        exit(1);
    }

    // 等待子进程结束
    waitpid(pid, NULL, 0);
    free(stack);
    printf("Child process finished\\n");
    return 0;
}