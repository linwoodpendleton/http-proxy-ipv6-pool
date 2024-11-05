// curl_callbacks.h
#ifndef CURL_CALLBACKS_H
#define CURL_CALLBACKS_H

#include <curl/curl.h>
#include <stddef.h>

// 结构体用于存储响应体
typedef struct {
    char *data;
    size_t size;
} MemoryStruct;

// 结构体用于存储响应头部
typedef struct {
    char **headers;
    size_t count;
} HeaderStruct;

#endif // CURL_CALLBACKS_H
