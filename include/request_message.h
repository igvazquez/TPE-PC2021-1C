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



typedef struct request_message_parser
{
    // array de headers los cuales me interesa detectar
    struct header *headers_to_detect;
    // cantidad de headers a tener en cuenta en headers_to_detect
    unsigned header_quantity;
    // contador de headers en headers_to_detect que no matchearon al momento de parsear
    unsigned mismatch_counter;
    // parser general del request message
    struct parser *rm_parser;
   
   // puntero al struct header que matcheo con el field name del header
    struct header *current_detection;


    // tamaño del body,si no hay body su valor es 0
    unsigned content_lenght;

    // indice para saber donde agregar el header en headers_to_detect
    unsigned add_index;


    /* storage del NAME del header
     * según el RFC 7230 el name del header no tiene un límite
     * nuestra aplicación decide usar el limite definido en MAX_HEADER_NAME_LENGTH el cual si se supera se devolverá el error correspondiente
     */
    uint8_t current_name_storage[MAX_HEADER_NAME_LENGTH+1];

    unsigned current_name_index;
} request_message_parser;

typedef enum
{
    HEADER_NOTHING = 0,
    HEADER_IGNORE = 1 << 0, // no deberia combinarse con nada
    HEADER_REPLACE = 1 << 1, // no deberia combinarse con nada
    HEADER_SEND = 1 << 2, // puede combinarse con STORAGE
    HEADER_STORAGE = 1 << 3, // puede combinarse con SEND
}header_interest;

struct header{
    // funcion que corre cuando se termina de leer el value del header
    void    (*on_value_end)(struct request_message_parser*parser);

   
    // parser del header name
    struct parser *name_parser;
    // booleano que establece el estado de detección del header
    bool* detected;
 
    header_interest interest;



    /* storage del value del header
     * según el RFC 7230 el value del header no tiene un límite
     * nuestra aplicación decide usar el limite definido en MAX_HEADER_VALUE_LENGTH el cual si se supera se devolverá el error correspondiente
     */
    uint8_t value_storage[MAX_HEADER_VALUE_LENGTH+1];

    // indice del value_storage
    unsigned value_index;
};

void header_parsers_feed(const struct parser_event* incoming,struct request_message_parser* parser);
void request_message_parser_init(struct request_message_parser*parser, unsigned header_quantity);
void add_header(struct request_message_parser *parser, char *header_name,header_interest interest ,const char* replacement, void (*on_value_end)(struct request_message_parser*parser));
void request_message_parser_reset(struct request_message_parser *parser);
void request_message_parser_destroy(struct request_message_parser *parser);
bool request_message_parser_process(const struct parser_event *e, request_message_parser *parser);
#endif