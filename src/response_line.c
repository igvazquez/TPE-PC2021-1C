#include "../include/response_line.h"
#include "../include/parser.h"
#include "../include/parser_utils.h"
#include "../include/mime_chars.h"
#include "../include/buffer.h"
#include <stdio.h>
#include <stdbool.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

enum state
{
    HTTP_VERSION_NAME0,
    HTTP_VERSION_NAME1,
    HTTP_VERSION_NAME2,
    HTTP_VERSION_NAME3,
    HTTP_VERSION_NAME4,
    HTTP_VERSION_MAJOR,
    HTTP_VERSION_DOT,
    HTTP_VERSION_MINOR,
    STATUS_CODE0,
    STATUS_CODE1,
    STATUS_CODE2,
    STATUS_CODE3,
    STATUS_MESSAGE,
    CR,
    CRLF,
    DONE,
    ERROR,
};

///////////////////////////////////////////////////////////////////////////////
// Acciones

static void
http_name(struct parser_event *ret, const uint8_t c) {
    ret->type    = RS_HTTP_NAME;
    ret->n       = 1;
    ret->data[0] = c;
}

static void
http_version_major(struct parser_event *ret, const uint8_t c) {
    ret->type    = RS_HTTP_VERSION_MAJOR;
    ret->n       = 1;
    ret->data[0] = c;
}

static void
http_version_minor(struct parser_event *ret, const uint8_t c) {
    ret->type    = RS_HTTP_VERSION_MINOR;
    ret->n       = 1;
    ret->data[0] = c;
}

static void
code(struct parser_event *ret, const uint8_t c) {
    ret->type    = RS_CODE;
    ret->n       = 1;
    ret->data[0] = c;
}

static void
code_end(struct parser_event *ret, const uint8_t c) {
    ret->type    = RS_CODE_END;
    ret->n       = 1;
    ret->data[0] = c;
}

static void
status_message(struct parser_event *ret, const uint8_t c) {
    ret->type    = RS_STATUS_MESSAGE;
    ret->n       = 1;
    ret->data[0] = c;
}

static void
unexpected(struct parser_event *ret, const uint8_t c) {
    ret->type    = RS_UNEXPECTED;
    ret->n       = 1;
    ret->data[0] = c;
}


static void
done(struct parser_event *ret, const uint8_t c) {
    ret->type    = RS_DONE;
    ret->n       = 0;
}


static void
wait(struct parser_event *ret, const uint8_t c) {
    ret->type    = RS_WAIT;
    ret->n       = 0;
}


///////////////////////////////////////////////////////////////////////////////
// Transiciones
static const struct parser_state_transition ST_HTTP_VERSION_NAME0[] =  {
        {.when = 'H',        .dest = HTTP_VERSION_NAME1,         .act1 = http_name,},
        {.when = 'h',        .dest = HTTP_VERSION_NAME1,         .act1 = http_name,},
        {.when = ANY,        .dest = ERROR,         .act1 = unexpected,},
};
static const struct parser_state_transition ST_HTTP_VERSION_NAME1[] =  {
        {.when = 'T',        .dest = HTTP_VERSION_NAME2,         .act1 = http_name,},
        {.when = 't',        .dest = HTTP_VERSION_NAME2,         .act1 = http_name,},
        {.when = ANY,        .dest = ERROR,         .act1 = unexpected,},
};
static const struct parser_state_transition ST_HTTP_VERSION_NAME2[] =  {
        {.when = 'T',        .dest = HTTP_VERSION_NAME3,         .act1 = http_name,},
        {.when = 't',        .dest = HTTP_VERSION_NAME3,         .act1 = http_name,},
        {.when = ANY,        .dest = ERROR,         .act1 = unexpected,},
};
static const struct parser_state_transition ST_HTTP_VERSION_NAME3[] =  {
        {.when = 'P',        .dest = HTTP_VERSION_NAME4,         .act1 = http_name,},
        {.when = 'p',        .dest = HTTP_VERSION_NAME4,         .act1 = http_name,},
        {.when = ANY,        .dest = ERROR,         .act1 = unexpected,},
};
static const struct parser_state_transition ST_HTTP_VERSION_NAME4[] =  {
        {.when = '/',        .dest = HTTP_VERSION_MAJOR,         .act1 = http_name,},
        {.when = ANY,        .dest = ERROR,         .act1 = unexpected,},
};
static const struct parser_state_transition ST_HTTP_VERSION_MAJOR[] =  {
        {.when = TOKEN_DIGIT,        .dest = HTTP_VERSION_DOT,         .act1 = http_version_major,},
        {.when = ANY,        .dest = ERROR,         .act1 = unexpected,},
};
static const struct parser_state_transition ST_HTTP_VERSION_DOT[] =  {
        {.when = '.',        .dest = HTTP_VERSION_MINOR,         .act1 = wait,},
        {.when = ANY,        .dest = ERROR,         .act1 = unexpected,},
};
static const struct parser_state_transition ST_HTTP_VERSION_MINOR[] =  {
        {.when = TOKEN_DIGIT,        .dest = STATUS_CODE0,         .act1 = http_version_minor,},
        {.when = ANY,        .dest = ERROR,         .act1 = unexpected,},
};
static const struct parser_state_transition ST_CODE0[] =  {
        {.when = ' ',        .dest = STATUS_CODE1,         .act1 = wait,},
        {.when = ANY,        .dest = ERROR,         .act1 = unexpected,},
};
static const struct parser_state_transition ST_CODE1[] =  {
        {.when = TOKEN_DIGIT,        .dest = STATUS_CODE2,         .act1 = code,},
        {.when = ANY,        .dest = ERROR,         .act1 = unexpected,},
};
static const struct parser_state_transition ST_CODE2[] =  {
        {.when = TOKEN_DIGIT,        .dest = STATUS_CODE3,         .act1 = code,},
        {.when = ANY,        .dest = ERROR,         .act1 = unexpected,},
};
static const struct parser_state_transition ST_CODE3[] =  {
        {.when = TOKEN_DIGIT,        .dest = STATUS_CODE3,         .act1 = code,},
        {.when = ' ',        .dest = STATUS_MESSAGE,         .act1 = code_end,},
        {.when = ANY,        .dest = ERROR,         .act1 = unexpected,},
};
static const struct parser_state_transition ST_STATUS_MESSAGE[] =  {
        {.when = TOKEN_BCHARS,        .dest = STATUS_MESSAGE,         .act1 = status_message,},
        {.when = '\r',        .dest = CR,         .act1 = wait,},
        {.when = ANY,        .dest = ERROR,         .act1 = unexpected,},
};

static const struct parser_state_transition ST_CR[] =  {
        {.when = '\n',        .dest = DONE,         .act1 = done,},
        {.when = ANY,        .dest = ERROR,         .act1 = unexpected,},
};

static const struct parser_state_transition ST_ERROR[] =  {
        {.when = ANY,        .dest = ERROR,         .act1 = unexpected,},
};

static const struct parser_state_transition ST_DONE[] =  {
        {.when = ANY,        .dest = ERROR,         .act1 = unexpected,},
};


///////////////////////////////////////////////////////////////////////////////
// Declaración formal
static const struct parser_state_transition *states[] =
        {
                ST_HTTP_VERSION_NAME0,
                ST_HTTP_VERSION_NAME1,
                ST_HTTP_VERSION_NAME2,
                ST_HTTP_VERSION_NAME3,
                ST_HTTP_VERSION_NAME4,
                ST_HTTP_VERSION_MAJOR,
                ST_HTTP_VERSION_DOT,
                ST_HTTP_VERSION_MINOR,
                ST_CODE0,
                ST_CODE1,
                ST_CODE2,
                ST_CODE3,
                ST_STATUS_MESSAGE,
                ST_CR,
                ST_DONE,
                ST_ERROR
        };

#define N(x) (sizeof(x)/sizeof((x)[0]))

static const size_t states_n [] = {
        N(ST_HTTP_VERSION_NAME0),
        N(ST_HTTP_VERSION_NAME1),
        N(ST_HTTP_VERSION_NAME2),
        N(ST_HTTP_VERSION_NAME3),
        N(ST_HTTP_VERSION_NAME4),
        N(ST_HTTP_VERSION_MAJOR),
        N(ST_HTTP_VERSION_DOT),
        N(ST_HTTP_VERSION_MINOR),
        N(ST_CODE0),
        N(ST_CODE1),
        N(ST_CODE2),
        N(ST_CODE3),
        N(ST_STATUS_MESSAGE),
        N(ST_CR),
        N(ST_DONE),
        N(ST_ERROR),
};

static struct parser_definition definition = {
        .states_count = N(states),
        .states       = states,
        .states_n     = states_n,
        .start_state  = HTTP_VERSION_NAME0,
};

const struct parser_definition * response_line_parser_definition(void){
    return &definition;
}

void response_line_parser_init(struct response_line_parser *parser)
{
    assert(parser != NULL);
    parser->rl_parser = parser_init(init_char_class(), response_line_parser_definition());
    if (parser->rl_parser == NULL)
    {
   
        abort();
    }
}

static status_code process_event(const struct parser_event * e, response_line_parser *parser){
    struct response_line * rl = parser->response_line;
    status_code status = OK;
    switch (e->type)
    {
        case RS_HTTP_VERSION_MAJOR:
            rl->version_major = e->data[0] - '0';
            break;
        case RS_HTTP_VERSION_MINOR:
            rl->version_minor = e->data[0] - '0';
            break;
        case RS_CODE:
            rl->status_code[(rl->code_counter)++] = e->data[0];
            break;
        case RS_CODE_END:
            rl->status_code[rl->code_counter] = '\0';
            break;
        case RS_STATUS_MESSAGE:
            if(rl->message_counter >= MAX_MSG_LENGTH){
                printf("counter >= max_msg_length\n");
                status = BAD_REQUEST;
                goto finally;
            }
            rl->status_message[(rl->message_counter)++] = e->data[0];
            break;
        case RS_DONE:
          /*  for(unsigned i = 0; i < e->n;i++){
                if(rl->message_counter >= MAX_MSG_LENGTH){
                    error = true;
                    goto finally;
                }
                rl->status_message[rl->message_counter++] = e->data[i];
            }*/
            rl->status_message[rl->message_counter] = '\0';
         
            break;
        case RS_WAIT:
            // nada
            break;
        default:
            break;
    }
finally:
    return status;
}

bool response_line_parser_consume(buffer *buffer, response_line_parser *parser, status_code *status){

    assert(parser != NULL && buffer != NULL);
    const struct parser_event *e;

    while (buffer_can_read(buffer))
    {
        uint8_t c = buffer_read(buffer);
    
        e = parser_feed(parser->rl_parser, c);
  
        do{
            if (response_line_is_done(e->type, status))
            {
                return true;
            }
            if((*status = process_event(e,parser))){
                //dio error
                return true;
            }
            e = e->next;
        } while (e != NULL);
    }
    return false;
}

void response_line_parser_reset(struct response_line_parser *parser){
    parser_reset(parser->rl_parser);
}

bool response_line_is_done(enum response_line_event_type type, status_code * status){

    switch(type){
        case RS_UNEXPECTED:
            *status = BAD_REQUEST;
            return true;
            break;
        case RS_DONE:

            *status = OK;
            return true;
            break;
        default:
            *status = OK;
            return false;
    };
    return false;
}
