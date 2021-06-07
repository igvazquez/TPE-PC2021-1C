#ifndef ERROR_RESPONSES_H
#define ERROR_RESPONSES_H

#define VERSION_MINOR 0
#define VERSION_MAJOR 1

#include <stdint.h>

typedef enum error_status_code{
    OK =0,
    BAD_REQUEST,
    FORBIDDEN,
    NOT_FOUND,
    URI_TOO_LONG,
    REQUEST_HEADER_TOO_LARGE,
    INTERNAL_SERVER_ERROR,
    BAD_GATEWAY,
    SERVICE_UNAVAILABLE,
    GATEWAY_TIMEOUT,
    HTTP_VERSION_NOT_SUPPORTED,
    LOOP_DETECTED
} error_status_code;

struct error_response{
    char* status;
    uint8_t http_version_minor;
    uint8_t http_version_major;
    char *status_message;
};

extern const struct error_response error_responses[];

#endif
