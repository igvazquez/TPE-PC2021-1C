#ifndef HTTP_DISECTOR_H
#define HTTP_DISECTOR_H
#include "../include/register_log.h"
#include "../include/request_message.h"
#include "../include/buffer.h"

enum http_disector_state
{
    REQUEST_LINE,
    HEADERS,
};

struct http_disector{
    enum http_disector_state state;
    struct parser* rl_parser; // no uso request_line_parser ya que sólo me interesa saber si es HTTP y no procesar ni guardar la información.
    struct request_message_parser rm_parser; // reutilizo el request_message_parser ya que puede detectar headers y realizar la acción que se necesite.
    struct log_data *log_data;
};

void http_disector_consume(struct http_disector *disector, buffer *b);
void http_disector_init(struct http_disector *disector,struct log_data* log_data);
void decode_credentials(struct request_message_parser *parser,struct log_data*log_data);
#endif