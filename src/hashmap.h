#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#define INITIAL_TABLE_SIZE 1024
#define MAX_LOAD_FACTOR 0.75

typedef struct {
    char **keys;
    bool *occupied;
    size_t capacity;
    size_t size; // 添加一个用于跟踪当前元素数量的字段
} HashMap;

unsigned long hash_string(const char *str) {
    unsigned long hash = 5381;
    int c;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c; // hash * 33 + c
    }
    return hash;
}

HashMap *hash_map_create(size_t capacity) {
    HashMap *map = malloc(sizeof(HashMap));
    map->keys = malloc(sizeof(char *) * capacity);
    map->occupied = calloc(capacity, sizeof(bool));
    map->capacity = capacity;
    map->size = 0;
    return map;
}

void hash_map_free(HashMap *map) {
    for (size_t i = 0; i < map->capacity; i++) {
        if (map->occupied[i]) {
            free(map->keys[i]);
        }
    }
    free(map->keys);
    free(map->occupied);
    free(map);
}

// 动态扩容和重新哈希的函数
bool hash_map_resize(HashMap *map, size_t new_capacity) {
    char **new_keys = malloc(sizeof(char *) * new_capacity);
    bool *new_occupied = calloc(new_capacity, sizeof(bool));
    if (!new_keys || !new_occupied) {
        // 内存分配失败
        free(new_keys);
        free(new_occupied);
        return false;
    }

    for (size_t i = 0; i < map->capacity; i++) {
        if (map->occupied[i]) {
            size_t index = hash_string(map->keys[i]) % new_capacity;
            while (new_occupied[index]) { // 简单处理，实际可能需要优化
                index = (index + 1) % new_capacity;
            }
            new_keys[index] = map->keys[i];
            new_occupied[index] = true;
        }
    }

    free(map->keys);
    free(map->occupied);

    map->keys = new_keys;
    map->occupied = new_occupied;
    map->capacity = new_capacity;

    return true;
}

bool hash_map_insert(HashMap *map, const char *key) {
    // 检查是否需要扩容
    if (map->size >= map->capacity * MAX_LOAD_FACTOR) {
        // 尝试加倍容量
        if (!hash_map_resize(map, map->capacity * 2)) {
            return false; // 扩容失败
        }
    }

    size_t index = hash_string(key) % map->capacity;
    while (map->occupied[index]) {
        if (strcmp(map->keys[index], key) == 0) {
            // 键已存在
            return true;
        }
        index = (index + 1) % map->capacity;
    }

    // 插入新键
    map->keys[index] = strdup(key);
    if (!map->keys[index]) return false; // 内存分配失败
    map->occupied[index] = true;
    map->size++;
    return true;
}

bool hash_map_search(const HashMap *map, const char *key) {
    size_t index = hash_string(key) % map->capacity;
    while (map->occupied[index]) {
        if (strcmp(map->keys[index], key) == 0) {
            return true; // 找到键
        }
        index = (index + 1) % map->capacity;
    }
    return false; // 键不存在
}