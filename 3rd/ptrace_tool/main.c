#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/user.h>
#include <sys/reg.h>

#include "../../src/file_dealer.h"
#include "../../src/data_dealer.h"

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <program-to-trace> [args]\n", argv[0]);
        exit(1);
    }

    SEQ **seq = (SEQ **)malloc(sizeof(SEQ *) * 1);
    con_syscall_init(seq, 8, 1);
    char *cs = (char *)malloc(sizeof(char) * 25);
    char dig[65] = { 0 };

    char *path = argv[1];
    char *filename = strrchr(path, '/');

    if (filename == NULL) {
        filename = path;
    } else {
        filename++;
    }

    char outFile[80] = "../../test/digest_lib";
    strcat(outFile, "/");
    strcat(outFile, filename);

    pid_t child = fork();

    if (child == 0) {
        // 子进程执行
        
        // 允许父进程跟踪此进程
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        
        // 停止自己，直到父进程准备好跟踪
        kill(getpid(), SIGSTOP);
        
        // 执行指定的程序
        execvp(argv[1], argv + 1);
        
        // execvp只有在出错的情况下才会返回
        perror("execvp");
        exit(1);
    } else {
        // 父进程执行
        int status;
        long syscall;
        char dig_syscall[64];

        waitpid(child, &status, 0); // 等待子进程停止

        // 设置跟踪选项
        ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACESYSGOOD);

        while (1) {
            // 继续执行，直到下一个系统调用开始
            ptrace(PTRACE_SYSCALL, child, 0, 0);
            waitpid(child, &status, 0);

            if (WIFEXITED(status)) break; // 如果子进程退出，则结束循环

            // 获取并打印系统调用号
            syscall = ptrace(PTRACE_PEEKUSER, child, sizeof(long)*ORIG_RAX, NULL);
	    printf("id %l\n", syscall);
            // TODO:将syscall放入序列（前面还要加个计数器），然后进行摘要计算并输出到文件（输出到二五年间已经写到下一行了，完善它）
            update_syscall_seq(seq[0], syscall);
            if (queueIsFull(seq[0])) {
                int len = combine_sequence(seq[0], &cs);
                digest_gen(cs, len, dig);
                int ret = out2File(dig, outFile);
                if (0 == ret) {
                    perror("Cannot write to file !");
                }
            }

            // 继续执行，直到系统调用结束
            ptrace(PTRACE_SYSCALL, child, 0, 0);
            waitpid(child, &status, 0);
            if (WIFEXITED(status)) break; // 如果子进程退出，则结束循环
        }
    }

    return 0;
}
