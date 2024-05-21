#include <stdio.h>
#include <stdlib.h>

int main() {
    FILE *fptr;
    
    // 尝试打开文件
    fptr = fopen("test.txt", "w");
    if (fptr == NULL) {
        printf("Error opening file!\\n");
        exit(1);
    }
    
    // 写入数据
    fprintf(fptr, "Evil!!\\n");

    printf("evil!");
    
    // 关闭文件
    fclose(fptr);
    
    return 0;
}
