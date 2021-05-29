#ifndef START_LINE_H
#define START_LINE_H

#include <stdint.h>
#include <stddef.h>
#include "../include/parser.h"
#include "../include/buffer.h"

#define MAX_DOMAIN_NAME_LEN 255 // Lo dice el RFC 1035
#define MAX_METHOD_LEN 8 // Los métodos de mayor longitud son OPTIONS y CONNECT 
#define MAX_IPV6_LEN  40// FFFF:FFFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF\0 = 4*8+7+1
#define MAX_IPV4_LEN  20// 255.2555.255.255\0 = 4*4+3+1

#define IPV4_REGEX  "((25[0-5]|2[0-4][0-9]|(1[0-9][0-9]|([1-9]?[0-9]))).){3}(25[0-5]|2[0-4][0-9]|(1[0-9][0-9]|([1-9]?[0-9])))"

enum start_line_state
{
    SL_METHOD,
    SL_REQUEST_TARGET_SCHEME,
    SL_REQUEST_TARGET_HOST,
    SL_REQUEST_TARGET_PORT,
    SL_REQUEST_TARGET_PATH,
    SL_HTTP_VERSION,
    SL_DONE,
    
    SL_ERROR_UNSUPPORTED_HTTP_VERSION,
    SL_ERROR_BAD_URI,
    SL_ERROR_UNSUPPORTED_METHOD
};


typedef enum {
    DOMAIN_NAME   = 1 << 0,
    IPV4    = 1 << 1,
    IPV6   = 1 << 2,
} addr_type ;

enum method_type
{
    GET,
    POST,
    PUT,
    DELETE,
    CONNECT,
    OPTIONS,
    HEAD,
    TRACE,
    ERROR_UNSUPPORTED_METHOD

};

enum start_line_event_type
{
    SL_METHOD0,
    SL_METHOD,
    SL_METHOD_END,
    SL_REQUEST_TARGET_SCHEME,
    SL_AUTHORITY,
    SL_REQUEST_TARGET_HOST,
    SL_REQUEST_TARGET_HOST_END,
    SL_REQUEST_TARGET_PORT,
    SL_REQUEST_TARGET_PATH,
    SL_HTTP_VERSION,
    SL_DONE,
    SL_ERROR_UNSUPPORTED_HTTP_VERSION,
    SL_ERROR_BAD_URI,
    SL_ERROR_UNSUPPORTED_METHOD

};

/** la definición del parser */
const struct parser_definition * start_line_parser(void);

struct start_line{
    addr_type addr_t;
    int port;
    //METHOD 
    char method_buffer[MAX_METHOD_LEN];
    unsigned method_counter;
    enum method_type method_type;
    //HOST
    
    unsigned host_counter;

    
    unsigned port_counter;

    union{
        char fqdn_or_ipv4[MAX_DOMAIN_NAME_LEN];
        char dir_ipv6[MAX_IPV6_LEN];
    } host;
};

typedef struct start_line_parser{
    enum start_line_state state;
    struct parser *scheme_parser;
    struct start_line * start_line;
} start_line_parser;

void start_line_parser_init(struct start_line_parser *parser);
enum start_line_state start_line_parser_feed(start_line_parser *parser, uint8_t c);
enum start_line_state start_line_parser_consume(buffer *buffer, start_line_parser *parser, bool *error);
bool start_line_is_done(enum start_line_state current_state, bool *error);

#endif