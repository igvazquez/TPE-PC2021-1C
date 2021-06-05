#ifndef ERROR_RESPONSES_H
#define ERROR_RESPONSES_H

#define HTTP_VERSION_MINOR 0
#define HTTP_VERSION_MAJOR 1

#include <stdint.h>

typedef enum status_code{
    BAD_REQUEST = 0,
    FORBIDDEN,
    NOT_FOUND,
    REQUEST_HEADER_TOO_LARGE,
    INTERNAL_SERVER_ERROR,
    BAD_GATEWAY,
    SERVICE_UNAVAILABLE,
    HTTP_VERSION_NOT_SUPPORTED,
    LOOP_DETECTED
} status_code;

struct error_response{
    char* status;
    uint8_t http_version_minor;
    uint8_t http_version_major;
    char *status_message;
};

extern const struct error_response error_responses[];

#endif
