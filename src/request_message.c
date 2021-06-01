#include "../include/parser.h"
#include "../include/parser_utils.h"
#include "../include/request_message.h"
#include "../include/mime_chars.h"
#include "../include/buffer.h"
#include <stdlib.h>
#include <assert.h>
enum states
{
    FIELD_NAME0,
    FIELD_NAME,
    FIELD_VALUE,
    FIELD_VALUE_CR,
    FIELD_VALUE_CRLF,
    FIELD_VALUE_CRLF_CR,
    BODY,
    ERROR
};

///////////////////////////////////////////////////////////////////////////////
// Acciones

static void
field_name(struct parser_event *ret, const uint8_t c) {
    ret->type    = RM_FIELD_NAME;
    ret->n       = 1;
    ret->data[0] = c;
}

static void
field_name_end(struct parser_event *ret, const uint8_t c) {
    ret->type    = RM_FIELD_NAME_END;
    ret->n       = 1;
    ret->data[0] = ':';
}

static void
value(struct parser_event *ret, const uint8_t c) {
    ret->type    = RM_FIELD_VALUE;
    ret->n       = 1;
    ret->data[0] = c;
}

static void
value_cr(struct parser_event *ret, const uint8_t c) {
    ret->type    = RM_FIELD_VALUE;
    ret->n       = 1;
    ret->data[0] = '\r';
}
/*
static void
value_fold_crlf(struct parser_event *ret, const uint8_t c) {
    ret->type    = MIME_MSG_VALUE_FOLD;
    ret->n       = 2;
    ret->data[0] = '\r';
    ret->data[1] = '\n';
}

static void
value_fold(struct parser_event *ret, const uint8_t c) {
    ret->type    = MIME_MSG_VALUE_FOLD;
    ret->n       = 1;
    ret->data[0] = c ;
}
*/
static void
value_end(struct parser_event *ret, const uint8_t c) {
    ret->type    = RM_FIELD_VALUE_END;
    ret->n       = 2;
    ret->data[0] = '\r';
    ret->data[1] = '\n';
}

static void
wait(struct parser_event *ret, const uint8_t c) {
    ret->type    = RM_WAIT;
    ret->n       = 0;
}

static void
body_start(struct parser_event *ret, const uint8_t c) {
    ret->type    = RM_BODY_START;
    ret->n       = 2;
    ret->data[0] = '\r';
    ret->data[1] = '\n';
}

static void
body(struct parser_event *ret, const uint8_t c) {
    ret->type    = RM_BODY;
    ret->n       = 1;
    ret->data[0] = c;
}

static void
unexpected(struct parser_event *ret, const uint8_t c) {
    ret->type    = RM_UNEXPECTED;
    ret->n       = 1;
    ret->data[0] = c;
}
///////////////////////////////////////////////////////////////////////////////
// Transiciones
static const struct parser_state_transition ST_FIELD_NAME0[] =  {
    {.when = ':',        .dest = ERROR,         .act1 = unexpected,},
    {.when = ' ',        .dest = ERROR,         .act1 = unexpected,},
    {.when = TOKEN_TCHAR,  .dest = FIELD_NAME,         .act1 = field_name,},
    {.when = ANY,        .dest = ERROR,         .act1 = unexpected,},
};

static const struct parser_state_transition ST_FIELD_NAME[] =  {
    {.when = ':',  .dest = FIELD_VALUE,         .act1 = field_name_end,},
    {.when = TOKEN_TCHAR,  .dest = FIELD_NAME,         .act1 = field_name,},
    {.when = ANY,        .dest = ERROR,         .act1 = unexpected,},
};

static const struct parser_state_transition ST_FIELD_VALUE[] =  {
    {.when = '\r',       .dest = FIELD_VALUE_CR,       .act1 = wait,      },
    {.when = ANY,        .dest = FIELD_VALUE,          .act1 = value,     },
};

static const struct parser_state_transition ST_FIELD_VALUE_CR[] =  {
    {.when = '\n',       .dest = FIELD_VALUE_CRLF,     .act1 = wait,},
    {.when = ANY,        .dest = FIELD_VALUE,          .act1 = value_cr,
                                                 .act2 = value,     },
};


static const struct parser_state_transition ST_FIELD_VALUE_CRLF[] =  {
    {.when = ':',        .dest = ERROR,          .act1 = unexpected,},
    {.when = '\r',       .dest = FIELD_VALUE_CRLF_CR,  .act1 = wait,},
 /*   {.when = TOKEN_LWSP, .dest = FOLD,           .act1 = value_fold_crlf,
                                                 .act2 = value_fold,},
    {.when = TOKEN_CTL,  .dest = ERROR,          .act1 = value_end,
                                                 .act2 = unexpected,},*/
    {.when = TOKEN_TCHAR, .dest = FIELD_NAME0,           .act1 = value_end,
                                                 .act2 = field_name,      },
    {.when = ANY,        .dest = ERROR,          .act1 = unexpected,},
};


static const struct parser_state_transition ST_FIELD_VALUE_CRLF_CR[] =  {
    {.when = '\n',        .dest = BODY,          .act1 = value_end,
                                                 .act2 = body_start,},
    {.when = ANY,         .dest = ERROR,         .act1 = value_end,
                                                 .act2 = unexpected,},
};

static const struct parser_state_transition ST_BODY[] =  {
    {.when = ANY,        .dest = BODY,           .act1 = body,},
};

static const struct parser_state_transition ST_ERROR[] =  {
    {.when = ANY,        .dest = ERROR,           .act1 = unexpected,},
};

///////////////////////////////////////////////////////////////////////////////
// Declaración formal

static const struct parser_state_transition *states[] = {
    ST_FIELD_NAME0,
    ST_FIELD_NAME,
    ST_FIELD_VALUE,
    ST_FIELD_VALUE_CR,
    ST_FIELD_VALUE_CRLF,
    ST_FIELD_VALUE_CRLF_CR,
    ST_BODY,
    ST_ERROR,
};

#define N(x) (sizeof(x)/sizeof((x)[0]))

static const size_t states_n [] = {
    N(ST_FIELD_NAME0),
    N(ST_FIELD_NAME),
    N(ST_FIELD_VALUE),
    N(ST_FIELD_VALUE_CR),
    N(ST_FIELD_VALUE_CRLF),
    N(ST_FIELD_VALUE_CRLF_CR),
    N(ST_BODY),
    N(ST_ERROR),
};

static struct parser_definition definition = {
    .states_count = N(states),
    .states       = states,
    .states_n     = states_n,
    .start_state  = FIELD_NAME0,
};

const struct parser_definition * request_line_parser_definition(void){
    return &definition;
}
static bool T = true;
static bool F = false;


void header_parsers_feed(struct parser_event* incoming,struct request_message_parser* parser)
{
    unsigned header_quantity = parser->header_quantity;

    struct header* h;
    struct parser_event *e;
    unsigned n = incoming->n;
    struct header *detected = NULL;
    for (unsigned i = 0; i < header_quantity; i++)
    {
        h = parser->headers_to_detect + i;
       if(h->detected == 0 || *h->detected){
           // si es la primera vez o ya dió detected = true (puede que el header name siga y lo vuelva false)
            for(unsigned j = 0; j< n; j++){
                e = parser_feed(h->name_parser,incoming->data[j]);
                do {
            
                    switch(e->type) {
                        case STRING_CMP_EQ:
                            h->detected = &T;
                            detected = h;

                            break;
                        case STRING_CMP_NEQ:
                            h->detected = &F;
                            parser->mismatch_counter++;
                            break;
                    }
                    e = e->next;
                } while (e != NULL);
            }
           
       }
       
    }
    parser->current_detection = detected;

}
bool request_message_is_done(enum request_message_event_type type, bool *error){
    return false;
}

bool request_message_parser_consume(buffer* buffer,struct request_message_parser * parser, bool *error){
    const struct parser_event *e;

    while (buffer_can_read(buffer))
    {
        uint8_t c = buffer_read(buffer);
        printf("Leo: %c\n", c);
        e = parser_feed(parser->rm_parser, c);
        printf("Estado: %d\n", e->type);
        do{
            if (request_message_is_done(e->type, error))
            {
                printf("request message done - error: %d", *error);
                if(*error == false){
                   // fill_request_line_data(parser, error);
                }
                return true;
            }
            if((*error = process_event(e,parser))){
                //dio error
                return true;
            }
            e = e->next;
        } while (e != NULL);
    }
    return false;
}

static header_parsers_reset(struct request_message_parser* parser){
    unsigned header_quantity = parser->header_quantity;
    struct header *h;
    for (unsigned i = 0; i < header_quantity; i++)
    {
        h = parser->headers_to_detect + i;
        parser_reset(h->name_parser);
        h->detected = NULL;
        h->value_index = 0;
    }
    parser->mismatch_counter = 0;
}

static bool header_value(struct header * h, struct parser_event* e){
    for(unsigned i; i < e->n;i++){
        if(h->value_index > MAX_HEADER_VALUE_LENGTH){
            return true;
        }
        h->value_storage[(h->value_index)++] = e->data[i];
    }
    return false;
}

static bool process_event(const struct parser_event *e, request_message_parser *parser)
{

    switch (e->type)
    {
        case RM_FIELD_NAME:
            if(parser->mismatch_counter != parser->header_quantity){
                header_parsers_feed(e, parser);
            }
         
            break;
        case RM_FIELD_NAME_END:
            
            header_parsers_reset(parser);
            break;
        case RM_FIELD_VALUE:
            if(parser->current_detection != NULL && parser->current_detection->want_storage){
                return header_value(parser->current_detection, e);
            }
        
            break;
        case RM_FIELD_VALUE_END:
            // si detecté algun header ya terminó
            struct header *current_detection = parser->current_detection;
            if (current_detection != NULL && current_detection->on_value_end != NULL){
                current_detection->on_value_end(parser);
            }
            parser->current_detection = NULL;
            break;
        default:
            break;
    }
    return false;
}

void request_message_parser_init(struct request_message_parser*parser, unsigned header_quantity){
    assert(parser != NULL);
    parser->rm_parser = parser_init(init_char_class(), request_line_parser_definition());
    if (parser->rm_parser == NULL)
    {
        printf("parser_init returned null");
        abort();
    }
    if(header_quantity > 0){
        parser->headers_to_detect = (struct header *) malloc(header_quantity* sizeof(struct header));
        if(parser->headers_to_detect == NULL){
            printf("parser_init returned null");
            abort();
        }
    }
    
    parser->header_quantity = 0;
    parser->mismatch_counter = 0;
    parser->current_detection = NULL;
    parser->content_lenght = 0;
    parser->add_index = 0;
}
bool add_header(struct request_message_parser *parser, char *header_name, bool want_storage, void (*on_value_end)(struct request_message_parser*parser)){
    assert(parser != NULL && header_name != NULL);
    if(parser->add_index >= parser->header_quantity){
        abort();
    }
    struct parser_definition def = parser_utils_strcmpi(header_name);
    struct parser *name_parser = parser_init(parser_no_classes(), &def);
    if(name_parser == NULL){
        aboert();
    }
    parser->headers_to_detect[parser->add_index++] = {
        .name_parser = name_parser,
        .on_value_end = on_value_end,
        .want_storage = want_storage,
        .detected = NULL,
        .value_index = 0,
        };
}
void request_message_parser_reset(struct request_message_parser *parser){
    header_parsers_reset(parser);
    parser->mismatch_counter = 0;
    parser->current_detection = NULL;
    parser->content_lenght = 0;
}

void request_message_parser_destroy(struct request_message_parser *parser){
  
    unsigned header_quantity = parser->header_quantity;
    struct header h;
    for (unsigned i = 0; i < header_quantity; i++)
    {
        h = parser->headers_to_detect[i];
        parser_utils_strcmpi_destroy(h.name_parser->def);
        parser_destroy(h.name_parser);
    }
    free(parser->headers_to_detect);
        
}