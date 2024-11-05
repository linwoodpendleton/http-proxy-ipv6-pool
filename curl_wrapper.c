// curl_wrapper.c
#include <curl/curl.h>

CURLcode get_response_code(CURL *curl, long *response_code) {
    return curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, response_code);
}
