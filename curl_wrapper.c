// curl_wrapper.c
#include <curl/curl.h>
#include "curl_callbacks.h"

// 获取响应码的函数
CURLcode get_response_code(CURL *curl, long *response_code) {
    return curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, response_code);
}

// 初始化 MemoryStruct
MemoryStruct* init_memory() {
    MemoryStruct *mem = malloc(sizeof(MemoryStruct));
    if(mem == NULL) {
        fprintf(stderr, "Failed to allocate MemoryStruct\n");
        return NULL;
    }
    mem->data = malloc(1);  // 初始分配
    mem->size = 0;          // 初始化大小
    if(mem->data == NULL) {
        fprintf(stderr, "Failed to allocate memory for data\n");
        free(mem);
        return NULL;
    }
    mem->data[0] = '\0';
    return mem;
}

// 初始化 HeaderStruct
HeaderStruct* init_headers() {
    HeaderStruct *headers = malloc(sizeof(HeaderStruct));
    if(headers == NULL) {
        fprintf(stderr, "Failed to allocate HeaderStruct\n");
        return NULL;
    }
    headers->headers = NULL;
    headers->count = 0;
    return headers;
}

// 释放 MemoryStruct
void free_memory(MemoryStruct *mem) {
    if(mem) {
        free(mem->data);
        free(mem);
    }
}

// 释放 HeaderStruct
void free_headers(HeaderStruct *headers) {
    if(headers) {
        for(size_t i = 0; i < headers->count; ++i) {
            free(headers->headers[i]);
        }
        free(headers->headers);
        free(headers);
    }
}
