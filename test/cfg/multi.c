#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(void)
{
	const char *msg = "Hello, World!\\n";
    ssize_t written = write(STDOUT_FILENO, msg, strlen(msg));
    if (written == -1) {
        // 错误处理
    } else {
	sleep(2);
    }
	return 0;
}