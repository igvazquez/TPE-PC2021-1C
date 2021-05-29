#include "../include/start_line.h"
#include "../include/parser.h"
#include "../include/parser_utils.h"
#include "../include/mime_chars.h"
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#define UNKOWN_ADDR_TYPE (DOMAIN_NAME | IPV4 | IPV6)
#define DOMAIN_NAME_OR_IPV4 (DOMAIN_NAME | IPV4)

 
static enum start_line_state scheme(struct parser *parser, uint8_t c);
static enum start_line_state host(struct start_line * sl, uint8_t c);

static enum start_line_state port(struct start_line *sl, uint8_t c);
static enum start_line_state path(struct start_line *sl, uint8_t c);

///////////////////////////////////////////////////////////////////////////////
// Acciones

static void
method(struct parser_event *ret, const uint8_t c) {
    ret->type    = SL_METHOD;
    ret->n       = 1;
    ret->data[0] = c;
}

static void
method_end(struct parser_event *ret, const uint8_t c) {
    ret->type    = SL_METHOD_END;
    ret->n       = 1;
    ret->data[0] = c;
}
static void
method_error(struct parser_event *ret, const uint8_t c) {
    ret->type    = SL_ERROR_UNSUPPORTED_METHOD;
    ret->n       = 1;
    ret->data[0] = c;
}

static void
scheme(struct parser_event *ret, const uint8_t c) {
    ret->type    = SL_REQUEST_TARGET_SCHEME;
    ret->n       = 1;
    ret->data[0] = c;
}


static void
scheme_error(struct parser_event *ret, const uint8_t c) {
    ret->type    = SL_ERROR_BAD_URI;
    ret->n       = 1;
    ret->data[0] = c;
}


///////////////////////////////////////////////////////////////////////////////
// Transiciones
static const struct parser_state_transition SL_METHOD0[] =  {
    {.when = ' ',        .dest = SL_ERROR_UNSUPPORTED_METHOD,         .act1 = method_error,},
    {.when = TOKEN_ALPHA,  .dest = SL_METHOD,         .act1 = method,},
    {.when = ANY,        .dest = SL_ERROR_UNSUPPORTED_METHOD,         .act1 = method_error,},
};


static const struct parser_state_transition SL_METHOD[] =  {
    {.when = ' ',        .dest = SL_REQUEST_TARGET_SCHEME,         .act1 = method_end,},
    {.when = TOKEN_ALPHA,  .dest = SL_METHOD,         .act1 = method,},
    {.when = ANY,        .dest = SL_ERROR_UNSUPPORTED_METHOD,         .act1 = method_error,},
};

static const struct parser_state_transition SL_REQUEST_TARGET_SCHEME1[] =  {
    {.when = 'h',        .dest = SL_REQUEST_TARGET_SCHEME2,         .act1 = scheme,},
    {.when = ANY,        .dest = SL_ERROR_UNSUPPORTED_METHOD,         .act1 = scheme_error,},
};
static const struct parser_state_transition SL_REQUEST_TARGET_SCHEME2[] =  {
    {.when = 't',        .dest = SL_REQUEST_TARGET_SCHEME3,         .act1 = scheme,},
    {.when = ANY,        .dest = SL_ERROR_UNSUPPORTED_METHOD,         .act1 = scheme_error,},
};

static const struct parser_state_transition SL_REQUEST_TARGET_SCHEME3[] =  {
    {.when = 't',        .dest = SL_REQUEST_TARGET_SCHEME4,         .act1 = scheme,},
    {.when = ANY,        .dest = SL_ERROR_UNSUPPORTED_METHOD,         .act1 = scheme_error,},
};

static const struct parser_state_transition SL_REQUEST_TARGET_SCHEME4[] =  {
    {.when = 'p',        .dest = SL_REQUEST_TARGET_SCHEME5,         .act1 = scheme,},
    {.when = ANY,        .dest = SL_ERROR_UNSUPPORTED_METHOD,         .act1 = scheme_error,},
};

static const struct parser_state_transition SL_REQUEST_TARGET_SCHEME5[] =  {
    {.when = ':',        .dest = SL_REQUEST_TARGET_SCHEME6,         .act1 = scheme,},
    {.when = ANY,        .dest = SL_ERROR_UNSUPPORTED_METHOD,         .act1 = scheme_error,},
};

static const struct parser_state_transition SL_REQUEST_TARGET_SCHEME6[] =  {
    {.when = '/',        .dest = SL_REQUEST_TARGET_SCHEME7,         .act1 = scheme,},
    {.when = ANY,        .dest = SL_ERROR_UNSUPPORTED_METHOD,         .act1 = scheme_error,},
};

static const struct parser_state_transition SL_REQUEST_TARGET_SCHEME7[] =  {
    {.when = '/',        .dest = SL_REQUEST_,         .act1 = scheme,},
    {.when = ANY,        .dest = SL_ERROR_UNSUPPORTED_METHOD,         .act1 = scheme_error,},
};

static const struct parser_state_transition SL_REQUEST_TARGET_SCHEME1[] =  {
    {.when = 'h',        .dest = SL_REQUEST_TARGET_SCHEME2,         .act1 = scheme,},
    {.when = ANY,        .dest = SL_ERROR_UNSUPPORTED_METHOD,         .act1 = scheme_error,},
};



void start_line_parser_init(struct start_line_parser *parser)
{
    parser->start_line->addr_t = (DOMAIN_NAME | IPV4 | IPV6); // Al principio no sabemos cual es
    parser->start_line->port = -1;                               // DEFAULT
    parser->start_line->method_counter = 0;
    parser->start_line->host_counter = 0;
    parser->start_line->port_counter = 0;
    const struct parser_definition d = parser_utils_strcmpi("http://");

    parser->scheme_parser = parser_init(parser_no_classes(), d);
    if (parser->scheme_parser == NULL)
    {
        printf("parser_init returned null");
        abort();
    }
}

enum start_line_state start_line_parser_consume(buffer *buffer, start_line_parser *parser, bool *error){

    enum start_line_state st = parser->state;
    bool done = false;
    while (buffer_can_read(buffer) && !done)
    {
        uint8_t c = buffer_read(buffer);
        st = start_line_parser_feed(parser, c);
        if (start_line_is_done(st, error))
        {
            done = true;
        }
    }
    return st;
}

static enum method_type get_method_type(char * method_buffer){
    if(strcmp(method_buffer,"GET") == 0){
        return GET;
    }else if(strcmp(method_buffer,"POST") == 0){
        return POST;
    }else  if(strcmp(method_buffer,"PUT") == 0){
        return PUT;
    }else  if(strcmp(method_buffer,"DELETE") == 0){
        return DELETE;
    }else  if(strcmp(method_buffer,"CONNECT") == 0){
        return CONNECT;
    }else  if(strcmp(method_buffer,"OPTIONS") == 0){
        return OPTIONS;
    }else  if(strcmp(method_buffer,"HEAD") == 0){
        return HEAD;
    }else  if(strcmp(method_buffer,"TRACE") == 0){
        return TRACE;
    }
        return ERROR_UNSUPPORTED_METHOD;
    
   
}

enum start_line_state start_line_parser_feed(start_line_parser *parser, uint8_t c){
    enum start_line_state current_state = parser->state;
    enum start_line_state ret = SL_DONE;
    switch(current_state){
        case SL_METHOD:
       
            printf("Lei caracter %c \n", c);
            if(c == ' '){
               
                parser->start_line->method_buffer[parser->start_line->method_counter] = '\0';
                parser->start_line->method_type = get_method_type(parser->start_line->method_buffer);
                ret = SL_REQUEST_TARGET_SCHEME;
            }else{
         
                parser->start_line->method_buffer[(parser->start_line->method_counter)++] = c;
                ret = SL_METHOD;
            }
            printf("method = %s\n",parser->start_line->method_buffer);
            break;
        case SL_REQUEST_TARGET_SCHEME:
            printf("scheme: %c\n", c);
            ret = scheme(parser->scheme_parser,c);
            break;
        case SL_REQUEST_TARGET_HOST:
            printf("en target_host: method = %s\n",parser->start_line->method_buffer);
            ret = host(parser->start_line, c);
          
            break;
        case SL_REQUEST_TARGET_PORT:
            ret = port(parser->start_line, c);
            break;
        case SL_REQUEST_TARGET_PATH:
            ret = path(parser->start_line, c);
            break;
        case SL_HTTP_VERSION:

            break;
        case SL_ERROR_UNSUPPORTED_METHOD:
            ret =  SL_ERROR_UNSUPPORTED_METHOD;
            break;
        case SL_ERROR_UNSUPPORTED_HTTP_VERSION:
            ret =  SL_ERROR_UNSUPPORTED_HTTP_VERSION;
            break;
        case SL_ERROR_BAD_URI:
            ret = SL_ERROR_BAD_URI;
            break;

        default:
            abort();
            break;
    }
    parser->state = ret;
    return ret;
}

bool start_line_is_done(enum start_line_state current_state, bool *error){

    assert(error != NULL);
    switch(current_state){
        case SL_ERROR_BAD_URI:
        case SL_ERROR_UNSUPPORTED_HTTP_VERSION:
        case SL_ERROR_UNSUPPORTED_METHOD:
            *error = true;
            return true;
            break;
        case SL_DONE:
            *error = false;
            return true;
            break;
        default:
            *error = false;
            return false;
    }
}

static enum start_line_state scheme(struct parser* parser,uint8_t c){
         enum string_cmp_event_types event_type = parser_feed(parser, c)->type;
         enum start_line_state ret = SL_ERROR_BAD_URI;
         switch (event_type)
         {
         case STRING_CMP_MAYEQ:
             ret = SL_REQUEST_TARGET_SCHEME;
             break;
         case STRING_CMP_EQ:
             ret = SL_REQUEST_TARGET_HOST;
             break;
         case STRING_CMP_NEQ:
             printf("scheme not equals bro\n");
             ret = SL_ERROR_BAD_URI;
             break;
         };

        return ret;
}

static enum start_line_state host(struct start_line * sl, uint8_t c){
    addr_type type = sl->addr_t;
    switch (type)
    {
    case UNKOWN_ADDR_TYPE:
        if(c == '['){
            sl->addr_t = IPV6;
        }else{
            sl->addr_t = DOMAIN_NAME_OR_IPV4;
        }
       
        break;
    case DOMAIN_NAME_OR_IPV4:
        if(c == ':'){
            return SL_REQUEST_TARGET_PORT;
        }else if(c == '/'){
            return SL_REQUEST_TARGET_PATH;
        }
        sl->host.fqdn_or_ipv4[sl->host_counter++] = c;

        break;
    case IPV6:
        if(c == ']'){
            return SL_REQUEST_TARGET_PORT;
        }
        sl->host.dir_ipv6[sl->host_counter++] = c;
        break;

        default:
        break;
        };
        return SL_REQUEST_TARGET_PATH;
}



static enum start_line_state port(struct start_line *sl, uint8_t c){
    addr_type type = sl->addr_t;
    switch (type){
        //asdas]:80 o asd]/
        case IPV6:
            if (c == ':')
            {
                if(sl->port == -1){
                    //no asigne puerto
                }
            }
           break;

           //localhost:80/ 
        case DOMAIN_NAME_OR_IPV4:
            if(c != ' ' && c!= '/'){
            };
            break;
        };

        return SL_REQUEST_TARGET_PATH;
}
static enum start_line_state path(struct start_line *sl, uint8_t c){
    return SL_ERROR_BAD_URI;
}