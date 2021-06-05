#include "../include/error_responses.h"

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