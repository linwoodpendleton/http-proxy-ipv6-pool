// curl_callbacks.c
#include "curl_callbacks.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// 写回调函数，用于处理响应体
size_t write_callback(char *ptr, size_t size, size_t nmemb, void *userdata) {
    size_t real_size = size * nmemb;
    MemoryStruct *mem = (MemoryStruct *)userdata;

    char *ptr_new = realloc(mem->data, mem->size + real_size + 1);
    if(ptr_new == NULL) {
        // 内存不足
        fprintf(stderr, "Not enough memory (realloc returned NULL)\n");
        return 0;
    }

    mem->data = ptr_new;
    memcpy(&(mem->data[mem->size]), ptr, real_size);
    mem->size += real_size;
    mem->data[mem->size] = 0;

    return real_size;
}

// 头回调函数，用于处理响应头部
size_t header_callback(char *ptr, size_t size, size_t nmemb, void *userdata) {
    size_t real_size = size * nmemb;
    HeaderStruct *headers = (HeaderStruct *)userdata;

    // 分配内存为新的头部
    char *header = malloc(real_size + 1);
    if(header == NULL) {
        fprintf(stderr, "Not enough memory (malloc returned NULL)\n");
        return 0;
    }

    memcpy(header, ptr, real_size);
    header[real_size] = '\0';

    // 添加到头部数组
    char **temp = realloc(headers->headers, sizeof(char*) * (headers->count + 1));
    if(temp == NULL) {
        fprintf(stderr, "Not enough memory (realloc returned NULL)\n");
        free(header);
        return 0;
    }

    headers->headers = temp;
    headers->headers[headers->count] = header;
    headers->count += 1;

    return real_size;
}
