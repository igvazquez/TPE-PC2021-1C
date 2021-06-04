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

const struct error_response error_responses[] = {
    {
        .status ="400",
        .http_version_minor = HTTP_VERSION_MINOR,
        .http_version_major = HTTP_VERSION_MAJOR,
        .status_message="Bad Request"
    },
    {
        .status ="403",
        .http_version_minor = HTTP_VERSION_MINOR,
        .http_version_major = HTTP_VERSION_MAJOR,
        .status_message="Forbidden"
    },
    {
        .status ="404",
        .http_version_minor = HTTP_VERSION_MINOR,
        .http_version_major = HTTP_VERSION_MAJOR,
        .status_message="Not Found"
    },
    {
        .status ="431",
        .http_version_minor = HTTP_VERSION_MINOR,
        .http_version_major = HTTP_VERSION_MAJOR,
        .status_message="Request Header Fields Too Large"
    },
    {
        .status ="500",
        .http_version_minor = HTTP_VERSION_MINOR,
        .http_version_major = HTTP_VERSION_MAJOR,
        .status_message="Internal Server Error"
    },
    {
        .status ="502",
        .http_version_minor = HTTP_VERSION_MINOR,
        .http_version_major = HTTP_VERSION_MAJOR,
        .status_message="Bad Gateway"
    },
    {
        .status ="503",
        .http_version_minor = HTTP_VERSION_MINOR,
        .http_version_major = HTTP_VERSION_MAJOR,
        .status_message="Service Unavailable"
    },
    {
        .status ="505",
        .http_version_minor = HTTP_VERSION_MINOR,
        .http_version_major = HTTP_VERSION_MAJOR,
        .status_message="HTTP Version Not Supported"
    },
    {
        .status ="508",
        .http_version_minor = HTTP_VERSION_MINOR,
        .http_version_major = HTTP_VERSION_MAJOR,
        .status_message="Loop Detected"
    }
};

#endif
