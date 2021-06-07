#include "../include/parser.h"
#include "../include/parser_utils.h"
#include "../include/request_message.h"
#include "../include/mime_chars.h"
#include "../include/buffer.h"
#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
enum states
{
    FIELD_NAME0,
    FIELD_NAME0_CR,
    FIELD_NAME,
    FIELD_VALUE0,
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
    {.when = '\r',        .dest = FIELD_NAME0_CR,         .act1 = wait,}, 
    {.when = ':',        .dest = ERROR,         .act1 = unexpected,},
    {.when = ' ',        .dest = ERROR,         .act1 = unexpected,},
    {.when = TOKEN_TCHAR,  .dest = FIELD_NAME,         .act1 = field_name,},
    {.when = ANY,        .dest = ERROR,         .act1 = unexpected,},
};

static const struct parser_state_transition ST_FIELD_NAME0_CR[] =  {
    {.when = '\n',        .dest = BODY,         .act1 = body_start,}, 
    {.when = ANY,        .dest = ERROR,         .act1 = unexpected,},
};

static const struct parser_state_transition ST_FIELD_NAME[] =  {
    {.when = ':',  .dest = FIELD_VALUE0,         .act1 = field_name_end,},
    {.when = TOKEN_TCHAR,  .dest = FIELD_NAME,         .act1 = field_name,},
    {.when = ANY,        .dest = ERROR,         .act1 = unexpected,},
};
static const struct parser_state_transition ST_FIELD_VALUE0[] =  {
    {.when = ' ',       .dest = FIELD_VALUE0,       .act1 = wait,      },
    {.when = ANY,        .dest = FIELD_VALUE,          .act1 = value,     },
};

static const struct parser_state_transition ST_FIELD_VALUE[] =  {
    {.when = '\r',       .dest = FIELD_VALUE_CR,       .act1 = wait,      },
    {.when = ANY,        .dest = FIELD_VALUE,          .act1 = value,     },
};

static const struct parser_state_transition ST_FIELD_VALUE_CR[] =  {
    {.when = '\n',       .dest = FIELD_VALUE_CRLF,     .act1 = value_end,},
    {.when = ANY,        .dest = FIELD_VALUE,          .act1 = value_cr,
                                                 .act2 = value,     },
};


static const struct parser_state_transition ST_FIELD_VALUE_CRLF[] =  {
    {.when = ':',        .dest = ERROR,          .act1 = unexpected,},
    {.when = '\r',       .dest = FIELD_VALUE_CRLF_CR,  .act1 = wait,},
    {.when = TOKEN_TCHAR, .dest = FIELD_NAME0,           .act1 = field_name,
                                                   },
    {.when = ANY,        .dest = ERROR,          .act1 = unexpected,},
};


static const struct parser_state_transition ST_FIELD_VALUE_CRLF_CR[] =  {
    {.when = '\n',        .dest = BODY,          .act1 = body_start,},
    {.when = ANY,         .dest = ERROR,         .act1 = unexpected,},
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
    ST_FIELD_NAME0_CR,
    ST_FIELD_NAME,
    ST_FIELD_VALUE0,
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
    N(ST_FIELD_NAME0_CR),
    N(ST_FIELD_NAME),
    N(ST_FIELD_VALUE0),
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

const struct parser_definition * request_message_parser_definition(void){
    return &definition;
}
static bool T = true;
static bool F = false;



void header_parsers_feed(const struct parser_event* incoming,struct request_message_parser* parser)
{

    unsigned header_quantity = parser->header_quantity;

    struct header* h;
    const struct parser_event *e;
    unsigned n = incoming->n;
    struct header *detected = NULL;
    for (unsigned i = 0; i < header_quantity; i++)
    {
 
        h = parser->headers_to_detect + i;
      
        if (h->detected == NULL || *h->detected == true)
        {
           
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



static void header_parsers_reset(struct request_message_parser* parser){
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

static bool save_data(const struct parser_event*e,struct request_message_parser * parser){
    struct header *  current_detection  = parser->current_detection;
    switch (e->type){
        case RM_FIELD_NAME_END:
            if(current_detection == NULL || !(current_detection->interest & HEADER_IGNORE)){
                memcpy(parser->data + parser->data_index, parser->current_name_storage, parser->current_name_index);
                parser->data_index += parser->current_name_index;
                parser->data[(parser->data_index)++] = ':';
                parser->data[(parser->data_index)++] = ' ';
            }    
        
            break;
        case RM_FIELD_VALUE:
            if(current_detection == NULL || (current_detection->interest & HEADER_SEND)){
                for (unsigned i = 0; i < e->n;i++){
                    parser->data[(parser->data_index)++] = e->data[i];
                }                       
            }
            break;
        case RM_FIELD_VALUE_END:
            // si detecté algun header, ya terminó
            if(current_detection != NULL && current_detection->interest & HEADER_REPLACE){
                size_t replace_len = strlen((char*)current_detection->value_storage);
                if(parser->data_size < parser->data_index + replace_len){
                    parser->data = (uint8_t *)realloc(parser->data, parser->data_size + replace_len+1);
                    if(parser->data == NULL){
 
                        return true;
                    }
                }
                char replacement_c = current_detection->value_storage[current_detection->value_index++];
                while(replacement_c != '\0'){
                    parser->data[(parser->data_index)++] = replacement_c;
                    replacement_c = current_detection->value_storage[current_detection->value_index++]; 
                }
                    current_detection->value_index = 0;
            } 
            if(current_detection == NULL || !(current_detection->interest & HEADER_IGNORE)){
                parser->data[(parser->data_index)++] = '\r';
                parser->data[(parser->data_index)++] = '\n';
            }

            break;
        case RM_BODY_START:
            for (unsigned i = 0; i < e->n;i++){
                parser->data[(parser->data_index)++] = e->data[i];                    
            }
            break;
        case RM_BODY:
            for (unsigned i = 0; i < e->n;i++){        
                parser->data[(parser->data_index)++] = e->data[i];      
            }
         /*   if(parser->content_lenght == 0){
                parser->data[(parser->data_index)++] = '\r';
                parser->data[(parser->data_index)++] = '\n';
            }*/
            break;
        default:
            break;
    }
    return false;
}


bool request_message_parser_process(const struct parser_event *e, request_message_parser *parser,bool *error,struct log_data * log_data)
{
    struct header *current_detection = parser->current_detection;
    switch (e->type)
    {
        case RM_FIELD_NAME:
            if (parser->mismatch_counter != parser->header_quantity)
            {
                header_parsers_feed(e, parser);
            }
            for (unsigned i = 0; i < e->n; i++){
                if(parser->current_name_index > MAX_HEADER_NAME_LENGTH){
                    *error = true;
                    return true;
                }
                parser->current_name_storage[parser->current_name_index++] = e->data[i];
            }
            break;
        case RM_FIELD_NAME_END:
            header_parsers_reset(parser);
            if(parser->save_data){
                save_data(e, parser);
            }
            parser->current_name_index = 0;
            break;
        case RM_FIELD_VALUE:
           // printf("VALUE: %c\n",(char)e->data[0]);
            if(current_detection != NULL && (current_detection->interest & HEADER_STORAGE)){
                for (unsigned i = 0; i < e->n; i++){
                    if(current_detection->value_index > MAX_HEADER_VALUE_LENGTH){
                        *error = true;
                        return true;
                    }
                    current_detection->value_storage[current_detection->value_index++] = e->data[i];
                }
            }
            if(parser->save_data){
                save_data(e, parser);
            }
            break;
        case RM_FIELD_VALUE_END:
            //printf("VALUE END\n");
            // si detecté algun header, ya terminó
            if(current_detection != NULL){
                if(current_detection->interest & HEADER_STORAGE){
                    current_detection->value_storage[current_detection->value_index++] = '\0';
                    current_detection->value_index = 0;
                }
                
                if (current_detection->on_value_end != NULL)
                {
                    //printf("ON VALUE END: %s\n", current_detection->value_storage);
                    current_detection->on_value_end(parser,log_data);
                }
            }
            if(parser->save_data){
                if(save_data(e, parser)){
                    *error = true;
                    return true;
                };
            }
            if(e->next == NULL){
     
                parser->current_detection = NULL;
            }
            break;
        case RM_BODY_START:
            //printf("BODY START: %c\n",e->data[0]);
            if(parser->save_data){
                save_data(e, parser);
            }
       
            if(parser->content_lenght == 0){
                return true;
            }
            break;
        case RM_BODY:
          
             for (unsigned i = 0; i < e->n;i++){
                if(parser->content_lenght > 0){
                        
                    parser->content_lenght--;
                     
                }else{
                     break;
                }           
            }
            
            if(parser->save_data){
                save_data(e, parser);
            }
            if(parser->content_lenght == 0){
                
                return true;
            }
            break;
        case RM_UNEXPECTED:
            *error = true;
            return true;
            break;
        default:
            break;
    }
    return false;
}



bool  request_message_parser_consume(struct request_message_parser * parser,buffer*b,bool * error,struct log_data * log_data){
    bool done = false;
    const struct parser_event *e;
    size_t rbytes;
    buffer_read_ptr(b, &rbytes);
    if(parser->save_data){
        if(parser->data == NULL){
            parser->data = (uint8_t *)malloc(rbytes+3);
            parser->data_size = rbytes;
        }else if(parser->data_size < rbytes){
            parser->data = (uint8_t *)realloc(parser->data,parser->data_size + rbytes);
        }
        if(parser->data == NULL){
            *error = true;
            done = true;
            goto finally;
        }
    }

    while (buffer_can_read(b) && !done)
    {  
        uint8_t c = buffer_read(b);  
        e = parser_feed(parser->rm_parser, c);
        do{
            done = request_message_parser_process(e,parser,error,log_data);
            // Podria meterlo todo en request_message_parser_process pero quiero reutilizar la funcion para el disector y no necesito esto
           
            if(done){
                if(*error){
                    goto finally;
                }
                break;
            }
            
            e = e->next;
        } while (e != NULL && !done);
    
    }

finally:
  
    return done;
}


void request_message_parser_init(struct request_message_parser*parser, unsigned header_quantity,bool save_data){
    assert(parser != NULL);
    parser->rm_parser = parser_init(init_char_class(), request_message_parser_definition());
    if (parser->rm_parser == NULL)
    {
 
        abort();
    }
    if(header_quantity > 0){
        parser->headers_to_detect = (struct header *) malloc(header_quantity* sizeof(struct header));
        if(parser->headers_to_detect == NULL){
         
            abort();
        }
    }
    
    parser->header_quantity = header_quantity;
    parser->mismatch_counter = 0;
    parser->current_detection = NULL;
    parser->content_lenght = 0;
    parser->add_index = 0;
    parser->current_name_index = 0;
    parser->save_data = save_data;
    parser->data_index = 0;
    parser->data_size = 0;
}
void add_header(struct request_message_parser *parser, char *header_name,header_interest interest ,const char* replacement, void (*on_value_end)(struct request_message_parser*parser,struct log_data* log_data)){
 
    assert(parser != NULL && header_name != NULL);
    if(parser->add_index >= parser->header_quantity){
        abort();
    }
    const struct parser_definition* def = parser_utils_strcmpi(header_name);
    struct parser *name_parser = parser_init(parser_no_classes(), def);
    if(name_parser == NULL){
        abort();
    }
    struct header *h = parser->headers_to_detect + parser->add_index++;
    h->name_parser = name_parser;
    h->on_value_end = on_value_end;
    h->value_index = 0;
    h->interest = interest;
    h->detected = NULL;
    if(replacement != NULL){
        memcpy(h->value_storage, replacement, MAX_HEADER_VALUE_LENGTH);
        free((char*)replacement);
    }

}
void request_message_parser_reset(struct request_message_parser *parser){
    assert(parser != NULL);
    header_parsers_reset(parser);
    parser->mismatch_counter = 0;
    parser->current_detection = NULL;
    parser->content_lenght = 0;
    parser->current_name_index = 0;
    parser_reset(parser->rm_parser);
}

void request_message_parser_destroy(struct request_message_parser *parser){
    assert(parser != NULL);
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

char *get_detection_value(struct request_message_parser *parser){
    assert(parser != NULL);
    if(parser->current_detection != NULL){
        return (char*)parser->current_detection->value_storage;
    }else{
        return NULL;
    }
}
void set_content_length(struct request_message_parser *parser, long content_length){
    assert(parser != NULL && content_length >= 0);
    parser->content_lenght = content_length;
}