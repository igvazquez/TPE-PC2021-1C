#ifndef RESPONSE_LINE_H
#define RESPONSE_LINE_H

#include <stdint.h>
#include <stddef.h>
#include <netinet/in.h>
#include "../include/parser.h"
#include "../include/buffer.h"
#include "../include/error_responses.h"

enum {

    /*
     * Los codigos de estado de http van entre el 1xx-5xx
     * http://www.iana.org/assignments/http-status-codes/http-status-codes.xhtml
     */
    MAX_CODE_LENGTH = 3,

    /*
     * Como el RFC no delimita este campo, el valor 64
     * para el largo del mensaje es completamente arbitrario
     */
    MAX_MSG_LENGTH = 64
};

struct response_line {
    /**
     * versión mayor de HTTP tal como vino por la red.
     * Ejemplo: '1' para HTTP/1.0
     */
    uint8_t version_major;

    /**
     * versión menor de HTTP tal como vino por la red.
     * Ejemplo: '0' para HTTP/1.0
     */
    uint8_t version_minor;

    /**
     * Codigo http
     */
    uint8_t status_code[MAX_CODE_LENGTH + 1];
    unsigned code_counter;
    uint8_t status_message[MAX_MSG_LENGTH + 1];
    unsigned message_counter;
};

enum response_line_event_type
{
    RS_HTTP_NAME,
    RS_HTTP_VERSION_MAJOR,
    RS_HTTP_VERSION_MINOR,
    RS_CODE,
    RS_CODE_END,
    RS_STATUS_MESSAGE,
    RS_WAIT,
    RS_DONE,
    RS_UNEXPECTED
};

typedef struct response_line_parser{
    struct parser * rl_parser;
    struct response_line *response_line;
} response_line_parser;

/** la definición del parser */
const struct parser_definition * response_line_parser_definition(void);
void response_line_parser_init(struct response_line_parser *parser);
bool response_line_parser_consume(buffer *buffer, response_line_parser *parser, status_code *status);
bool response_line_is_done(enum response_line_event_type type, status_code * status);
void response_line_parser_reset(struct response_line_parser *p);

#endif //RESPONSE_LINE_H