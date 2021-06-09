#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "../include/doh_client.h"


char * EXPECTED_VERSION = "HTTP/1.0";
char * EXPECTED_STATUS_CODE = "200";
char * EXPECTED_STATUS_MSG = "OK";
char * EXPECTED_HEADER_CONTENT_START = "content-";
char * EXPECTED_HEADER_TYPE = "type:";
char * EXPECTED_HEADER_TYPE_VALUE = "application/dns-message";
char * EXPECTED_HEADER_LENGTH = "length:";




void eat_byte(doh_response * http_response, unsigned char byte) {
    switch(http_response->current_state) {
        case version:
            if (EXPECTED_VERSION[http_response->state_bytes_read] != byte) {
                if (http_response->state_bytes_read == (int)strlen(EXPECTED_VERSION) && byte == ' ') {
                    http_response->current_state = status_code;
                    http_response->state_bytes_read = 0;
                } else {
                    http_response->current_state = error;
                }

            } else {
                http_response->state_bytes_read++;
            }
            break;

        case status_code:
            if (EXPECTED_STATUS_CODE[http_response->state_bytes_read] != byte) {
                if (http_response->state_bytes_read == (int)strlen(EXPECTED_STATUS_CODE) && byte == ' ') {
                    http_response->current_state = status_msg;
                    http_response->state_bytes_read = 0;
                } else {
                    http_response->current_state = error;
                }

            } else {
                http_response->state_bytes_read++;
            }
            break;

        case status_msg:
            if (EXPECTED_STATUS_MSG[http_response->state_bytes_read] != byte) {
                    http_response->current_state = error;
            } else {
                http_response->state_bytes_read++;
                if(http_response->state_bytes_read == (int)strlen(EXPECTED_STATUS_MSG)){
                    http_response->current_state = waiting_crlf;//waiting_header_content;
                    http_response->state_bytes_read = 0;
                }
            }
            break;

        case waiting_crlf:
            if (byte == '\r') {
                if (http_response->state_bytes_read == 0)
                    http_response->state_bytes_read++;
                else
                    http_response->current_state = error;
            } else if (byte == '\n') {
                if (http_response->state_bytes_read <= 1) {
                    http_response->line_index = 0;
                    http_response->current_state = waiting_header_content;
                } else {
                    http_response->current_state = error;
                }
            } else {
                http_response->current_state = error;
            }
            break;

        case waiting_header_content:
            if (http_response->line_index == 0 && (byte == '\r' || byte == '\n')) {
                http_response->current_state = error;
            } else if (byte == '\n' && http_response->line_index > 0) {
                http_response->line_index = 0;
            } else {
                http_response->line_index++;
                if (http_response->state_bytes_read == (int)strlen(EXPECTED_HEADER_CONTENT_START)) {
                    if (tolower(byte) == EXPECTED_HEADER_LENGTH[0] && http_response->content_length == -1) {
                        http_response->current_state = waiting_header_length;
                        http_response->state_bytes_read = 1;
                    } else if (tolower(byte) == EXPECTED_HEADER_TYPE[0] && http_response->is_dns_message == 0) {
                        http_response->current_state = waiting_header_type;
                        http_response->state_bytes_read = 1;
                    } else {
                        http_response->state_bytes_read = 0;
                    }
                } else if (EXPECTED_HEADER_CONTENT_START[http_response->state_bytes_read] != tolower(byte)) {
                    http_response->state_bytes_read = 0;
                } else {
                    http_response->state_bytes_read++;
                }

            }
            break;

        case waiting_header_type:
            if (byte == '\n' && http_response->line_index > 0) {
                http_response->current_state = error;
            } else {
                http_response->line_index++;
                if (http_response->state_bytes_read == (int)strlen(EXPECTED_HEADER_TYPE)) {
                    if(byte == ' ') {
                        http_response->state_bytes_read = 0;
                        http_response->current_state = waiting_header_type_value;
                    } else if (tolower(byte) != EXPECTED_HEADER_TYPE_VALUE[0]) {
                        http_response->current_state = error;
                    } else {
                        http_response->state_bytes_read = 1;
                        http_response->current_state = waiting_header_type_value;
                    }

                } else if (EXPECTED_HEADER_TYPE[http_response->state_bytes_read] != tolower(byte)) {
                    http_response->current_state = waiting_header_content;
                    http_response->state_bytes_read = 0;
                } else {
                    http_response->state_bytes_read++;
                }

            }
            break;

        case waiting_header_length:
            if (byte == '\n' && http_response->line_index > 0) {
                http_response->current_state = error;
            } else {
                http_response->line_index++;

                if (http_response->state_bytes_read == (int)strlen(EXPECTED_HEADER_LENGTH)) {
                    if(byte == ' ') {
                        http_response->content_length = 0;
                        http_response->state_bytes_read = 0;
                        http_response->current_state = waiting_header_length_value;
                    } else if (! isdigit(byte)) {
                        http_response->current_state = error;
                    } else {
                        http_response->content_length = byte - '0';
                        http_response->state_bytes_read = 1;
                        http_response->current_state = waiting_header_length_value;
                    }

                } else if (EXPECTED_HEADER_LENGTH[http_response->state_bytes_read] != tolower(byte)) {
                    http_response->current_state = waiting_header_content;
                    http_response->state_bytes_read = 0;
                } else {
                    http_response->state_bytes_read++;
                }

            }
            break;

        case waiting_header_type_value:
            if(tolower(byte) != EXPECTED_HEADER_TYPE_VALUE[http_response->state_bytes_read]) {
                http_response->current_state = error;
            } else {
                http_response->state_bytes_read++;
                if(http_response->state_bytes_read == (int)strlen(EXPECTED_HEADER_TYPE_VALUE)) {
                    http_response->is_dns_message = 1;
                    http_response->state_bytes_read = 0;
                    if(http_response->content_length == -1)
                        http_response->current_state = waiting_crlf;
                    else
                        http_response->current_state = waiting_end_of_header;

                }
            }
            break;

        case waiting_header_length_value:
            if(isdigit(byte)) {
                http_response->content_length *= 10;
                http_response->content_length += byte - '0';
                http_response->state_bytes_read++;
            } else if(byte == '\r') {
            } else if(byte == '\n') {
                http_response->state_bytes_read = 0;
                http_response->line_index = 0;
                if(http_response->is_dns_message == 0)
                    http_response->current_state = waiting_header_content;
                else
                    http_response->current_state = waiting_instant_line_break;

            } else {
                http_response->current_state = error;
            }
            break;

        case waiting_instant_line_break:

            if(byte == '\n' && http_response->state_bytes_read == 0) {
                http_response->state_bytes_read = 0;
                http_response->current_state = reading_data;
            } else if(byte == '\r' && http_response->state_bytes_read == 0) {
                http_response->state_bytes_read++;
            } else if(byte == '\n' && http_response->state_bytes_read == 1) {
                http_response->state_bytes_read = 0;
                http_response->current_state = reading_data;
            } else {
                http_response->state_bytes_read = 0;
                http_response->current_state = waiting_end_of_header;
            }
            break;

        case waiting_end_of_header:
            if(byte == '\n') {
                http_response->current_state = waiting_instant_line_break;
            }
            break;

        case reading_data:
            if(http_response->state_bytes_read == 0) {
                http_response->dns_response = malloc(http_response->content_length);
                if(!http_response->dns_response) {
                    http_response->current_state = error;
                    break;
                }
            }
            if(http_response->state_bytes_read < http_response->content_length -1) {
                http_response->dns_response[http_response->state_bytes_read++] = byte;
            } else {
                http_response->current_state = finished;
            }
            break;
        default:
            break;
    }

}


