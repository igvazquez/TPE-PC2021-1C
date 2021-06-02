#ifndef START_LINE_H
#define START_LINE_H

#include <stdint.h>
#include <stddef.h>
#include <netinet/in.h>
#include "../include/parser.h"
#include "../include/buffer.h"


#define IPV4_REGEX  "((25[0-5]|2[0-4][0-9]|(1[0-9][0-9]|([1-9]?[0-9]))).){3}(25[0-5]|2[0-4][0-9]|(1[0-9][0-9]|([1-9]?[0-9])))"
#define DEFAULT_HTTP_PORT 80
#include <netinet/in.h>

/**
 * request_line.c - parser para la primer línea de un request HTTP.
 *
 */

/*
 * arrancamos definiendo la informacion que queremos tener al momento
 * la primera línea. Es decir todo lo necesario para conectarse al origen
 * y para enviar la primera línea al origen
 */

// algunas constantes
enum {
    /**
     *  longitud maxima que toleramos para un metodo HTTP
     *  <http://www.iana.org/assignments/http-methods/http-methods.xhtml>
     *  $ curl -s http://www.iana.org/assignments/http-methods/methods.csv |
     *    cut -d, -f1 | awk '{print length($1)}' | sort -nr | head -n1
     *  17
     *
     *  entonces le damos changüi.
     */
    MAX_METHOD_LENGTH = 24,

    /** longitud maxima de un FQDN de DNS */
    MAX_FQDN_LENGTH   = 0xFF,

    MAX_ORIGIN_FORM   = 1 << 10,
    MAX_IPV6_LENGTH   =  39
};

/*
 * request-line   = method SP request-target SP HTTP-version CRLF
 * method         = token
 * request-target = absolute-form | authority-form # authority para connect
 */
struct request_line {
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
     * método HTTP (NUL terminated) tal como vino
     * GET | POST | …
     */
    uint8_t method[MAX_METHOD_LENGTH + 1];
    
   

    struct {
        // el tipo de request_target.
        enum {
            absolute_form,
            authority_form,
        } type;

        /** declara como está especificado el host*/
        enum request_line_addr_type {
            domain_addr_t,
            ipv4_addr_t,
            ipv6_addr_t,
        } host_type;
        
    
        // host y port aplican a todos

        /** el host al cual hay que conectarse puede estar escrito de tres formas */
        union {
            /** especificado con un nombre que se debe resolver (NUL-terminated) */
            char                domain[MAX_FQDN_LENGTH + 1];
            /** especificada como una dirección IPV4 */
            struct sockaddr_in  ipv4;
            /** especificada como una dirección IPV6 */
            struct sockaddr_in6 ipv6;
        } host;

        /** port in network byte order */
        in_port_t port;

        //////////////////////////////////////////////////////////////////////
        // en cierta forma absolute_form incluye un origin-form cuando se lo
        // separa en host | port y el resto.
        // 5.3.1.  origin-form
        // The most common form of request-target is the origin-form.
        // origin-form    = absolute-path [ "?" query ]
        uint8_t origin_form[MAX_ORIGIN_FORM];
    } request_target;

};





enum request_line_event_type
{
    RL_METHOD, 
    RL_METHOD_END, 
    RL_SCHEME, 
    RL_HOST,
    RL_HOST_END,
    RL_IPV6_0,
    RL_IPV6,
    RL_IPV6_END,
    RL_PORT,
    RL_ORIGIN_FORM,
    RL_ORIGIN_FORM_END,
    RL_HTTP_NAME,
    RL_HTTP_VERSION_MAJOR,
    RL_HTTP_VERSION_MINOR,
    RL_WAIT,
    RL_DONE,
    RL_UNEXPECTED
   
};

/** la definición del parser */
const struct parser_definition * start_line_parser_definition(void);

struct parsed_info{
    uint8_t version_major;
    uint8_t version_minor;
    //addr_type addr_t;
    unsigned short port;
    //METHOD 
    char method_buffer[MAX_METHOD_LENGTH +1];
    unsigned method_counter;
    //HOST
    enum parsed_info_addr_type {
            domain_or_ipv4_addr,
            ipv6_addr,
    } host_type;

    unsigned host_counter;
    union{
         char domain_or_ipv4_buffer[MAX_FQDN_LENGTH + 1];
         char ipv6_buffer[MAX_IPV6_LENGTH+1];
    } host;

    //ORIGIN FORM
    uint8_t origin_form_buffer[MAX_ORIGIN_FORM];
    unsigned origin_form_counter;
};

typedef struct request_line_parser{
    struct parser * rl_parser;
    struct request_line *request_line;
    struct parsed_info parsed_info;
} request_line_parser;

void request_line_parser_init(struct request_line_parser *parser);
//enum start_line_state start_line_parser_feed(start_line_parser *parser, uint8_t c);
bool request_line_parser_consume(buffer *buffer, request_line_parser *parser, bool *error);
bool request_line_is_done(enum request_line_event_type type, bool *error);
void request_line_parser_reset(struct request_line_parser *p);
#endif