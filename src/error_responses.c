#include "../include/error_responses.h"

const struct error_response error_responses[] = {
    {
        .status ="200",
        .http_version_minor = VERSION_MINOR,
        .http_version_major = VERSION_MAJOR,
        .status_message="OK"
    },
    {
        .status ="400",
        .http_version_minor = VERSION_MINOR,
        .http_version_major = VERSION_MAJOR,
        .status_message="Bad Request"
    },
    {
        .status ="403",
        .http_version_minor = VERSION_MINOR,
        .http_version_major = VERSION_MAJOR,
        .status_message="Forbidden"
    },
    {
        .status ="404",
        .http_version_minor = VERSION_MINOR,
        .http_version_major = VERSION_MAJOR,
        .status_message="Not Found"
    },
    {
        .status ="414",
        .http_version_minor = VERSION_MINOR,
        .http_version_major = VERSION_MAJOR,
        .status_message="URI Too Long"
    },
    {
        .status ="431",
        .http_version_minor = VERSION_MINOR,
        .http_version_major = VERSION_MAJOR,
        .status_message="Request Header Fields Too Large"
    },
    {
        .status ="500",
        .http_version_minor = VERSION_MINOR,
        .http_version_major = VERSION_MAJOR,
        .status_message="Internal Server Error"
    },
    {
        .status ="501",
        .http_version_minor = VERSION_MINOR,
        .http_version_major = VERSION_MAJOR,
        .status_message="Not implemented"
    },
    {
        .status ="502",
        .http_version_minor = VERSION_MINOR,
        .http_version_major = VERSION_MAJOR,
        .status_message="Bad Gateway"
    },
    {
        .status ="503",
        .http_version_minor = VERSION_MINOR,
        .http_version_major = VERSION_MAJOR,
        .status_message="Service Unavailable"
    },
    {
        .status ="504",
        .http_version_minor = VERSION_MINOR,
        .http_version_major = VERSION_MAJOR,
        .status_message="Gateway Timeout"
    },
    {
        .status ="505",
        .http_version_minor = VERSION_MINOR,
        .http_version_major = VERSION_MAJOR,
        .status_message="HTTP Version Not Supported"
    },
    {
        .status ="508",
        .http_version_minor = VERSION_MINOR,
        .http_version_major = VERSION_MAJOR,
        .status_message="Loop Detected"
    }
};
