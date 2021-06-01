#ifndef REQUEST_MESSAGE_H
#define REQUEST_MESSAGE_H

#include "../include/parser_utils.h"
#include "../include/parser.h"
#include "../include/buffer.h"
#include <stdbool.h>
#include <unistd.h>
#include <stdint.h>
#define MAX_HEADER_NAME_LENGTH 64
#define MAX_HEADER_VALUE_LENGTH 128

struct parser;
enum request_message_event_type
{
    /* caracter del nombre de un header. payload: caracter. */
    RM_FIELD_NAME,
    RM_FIELD_NAME_END,
    RM_FIELD_VALUE,
    RM_FIELD_VALUE_END,
    /* no tenemos idea de qué hacer hasta que venga el proximo caracter */
    RM_WAIT,
    RM_BODY_START,
    RM_BODY,

    /* se recibió un caracter que no se esperaba */
    RM_UNEXPECTED,
   
};

/** la definición del parser */
const struct parser_definition * request_headers_parser(void);

// header parsing information

struct header{
    // funcion que corre cuando se termina de leer el value del header
    void    (*on_value_end)(struct request_message_parser*parser);
    /* storage del value del header
     * según el RFC 7230 el value del header no tiene un límite
     * nuestra aplicación decide usar el limite definido en MAX_HEADER_VALUE_LENGTH el cual si se supera se devolverá el error correspondiente
     */
    uint8_t value_storage[MAX_HEADER_VALUE_LENGTH+1];
    // indice del value_storage
    unsigned value_index;
    // parser del header name
    struct parser *name_parser;
    // booleano que establece el estado de detección del header
    bool* detected;
    // booleano que establece si nos interesa guardar el value del header
    bool want_storage;
};

typedef struct request_message_parser
{
    struct header *headers_to_detect;
    // cantidad de headers a tener en cuenta en headers_to_detect
    unsigned header_quantity;
    // cantidad de headers en headers_to_detect que no matchearon al momento de parsear
    unsigned mismatch_counter;
    // parser general del request message
    struct parser *rm_parser;
   
   // puntero al struct header que matcheo con el field name del header
    struct header *current_detection;

    // tamaño del body,si no hay body su valor es 0
    unsigned content_lenght;

    // indice para saber donde agregar el header en headers_to_detect
    unsigned add_index;

} request_message_parser;
void header_parsers_feed(struct parser_event* incoming,struct request_message_parser* parser);
bool request_message_parser_consume(buffer* buffer,struct request_message_parser *parser,bool*error);
bool request_message_is_done(enum request_message_event_type type, bool *error);
void request_message_parser_init(struct request_message_parser*parser, unsigned header_quantity);
bool add_header(struct request_message_parser *parser, char *header_name, bool want_storage, void (*on_value_end)(struct request_message_parser*parser));
void request_message_parser_reset(struct request_message_parser *parser);
void request_message_parser_destroy(struct request_message_parser *parser);
#endif