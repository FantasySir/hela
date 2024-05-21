// #include "../../src/hashmap.h"
#include "../../src/file_dealer.h"

int main() {
    // 测试代码
    char *file = "../digest_lib/ls";
    HashMap *map = hash_map_create(INITIAL_TABLE_SIZE);
    read2map(file, map);
    if (hash_map_search(map, "39df18feeee02e8a4e56dcb993f14d7a025b98b541a381841777d0136bd94a33")) {
        printf("Find it ! \n");
    } else {
        printf("Not found！\n");
    }
    
    hash_map_free(map);
    return 0;
}