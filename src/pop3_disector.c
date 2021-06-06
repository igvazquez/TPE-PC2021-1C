#include "../include/pop3_disector.h"
#include "../include/mime_chars.h"
#include "../include/register_log.h"
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
enum state
{
    GREETING_PLUS,
    GREETING_O,
    GREETING_OK,
    GREETING_MESSAGE,
    GREETING_CR,
    USER0,
    USER1,
    USER2,
    USER3,
    USER4,
    USER_VALUE,
    USER_VALUE_CR,
    USER_CHECK_PLUS,
    USER_CHECK_O,
    USER_CHECK_OK,
    USER_ACCEPTED_MESSAGE,
    USER_ACCEPTED_CR,
    PASS0,
    PASS1,
    PASS2,
    PASS3,
    PASS4,
    PASS_VALUE,
    PASS_VALUE_CR,
    PASS_CHECK_PLUS,
    PASS_CHECK_O,
    PASS_CHECK_OK,
    DONE,
    ERROR,

};
///////////////////////////////////////////////////////////////////////////////
// Acciones
static void
user_value(struct parser_event *ret, const uint8_t c) {
    ret->type    = POP3_USER_VALUE;
    ret->n       = 1;
    ret->data[0] = c;
}

static void
user_value_end(struct parser_event *ret, const uint8_t c) {
    ret->type    = POP3_USER_VALUE_END;
    ret->n       = 1;
    ret->data[0] = c;
}

static void
pass_value(struct parser_event *ret, const uint8_t c) {
    ret->type    = POP3_PASS_VALUE;
    ret->n       = 1;
    ret->data[0] = c;
}

static void
pass_value_end(struct parser_event *ret, const uint8_t c) {
    ret->type    = POP3_PASS_VALUE_END;
    ret->n       = 1;
    ret->data[0] = c;
}

static void
message(struct parser_event *ret, const uint8_t c) {
    ret->type    = POP3_MESSAGE;
    ret->n       = 0;

}
static void
message_end(struct parser_event *ret, const uint8_t c) {
    ret->type    = POP3_MESSAGE_END;
    ret->n       = 0;

}

static void
unexpected(struct parser_event *ret, const uint8_t c) {
    ret->type    = POP3_UNEXPECTED;
    ret->n       = 1;
    ret->data[0] = c;
}

static void
wait(struct parser_event *ret, const uint8_t c) {
    ret->type    = POP3_WAIT;
    ret->n       = 0;
}

static void
done(struct parser_event *ret, const uint8_t c) {
    ret->type    = POP3_DONE;
    ret->n       = 0;
}

///////////////////////////////////////////////////////////////////////////////
// Transiciones

static const struct parser_state_transition ST_GREETING_PLUS[] =  {
    {.when = '+',        .dest = GREETING_O,         .act1 = message,},
    {.when = ANY,        .dest = ERROR,         .act1 = unexpected,},
};

static const struct parser_state_transition ST_GREETING_O[] =  {
    {.when = 'O',        .dest = GREETING_OK,         .act1 = message,},
    {.when = ANY,        .dest = ERROR,         .act1 = unexpected,},
};

static const struct parser_state_transition ST_GREETING_OK[] =  {
    {.when = 'K',        .dest = GREETING_MESSAGE,         .act1 = message,},
    {.when = ANY,        .dest = ERROR,         .act1 = unexpected,},
};

static const struct parser_state_transition ST_GREETING_MESSAGE[] =  {
    {.when = '\r',        .dest = GREETING_CR,         .act1 = message,},
    {.when = ANY,        .dest = GREETING_MESSAGE,         .act1 = message,},
   
};

static const struct parser_state_transition ST_GREETING_CR[] =  {
    {.when = '\n',        .dest = USER0,         .act1 = message_end,},
    {.when = ANY,        .dest = ERROR,         .act1 = unexpected,},
   
};

static const struct parser_state_transition ST_USER0[] =  {
    {.when = 'U',        .dest = USER1,         .act1 = wait,},
    {.when = 'u',        .dest = USER1,         .act1 = wait,},
    {.when = ANY,        .dest = ERROR,         .act1 = unexpected,},
   
};

static const struct parser_state_transition ST_USER1[] =  {
    {.when = 'S',        .dest = USER2,         .act1 = wait,},
    {.when = 's',        .dest = USER2,         .act1 = wait,},
    {.when = ANY,        .dest = ERROR,         .act1 = unexpected,},
   
};

static const struct parser_state_transition ST_USER2[] =  {
    {.when = 'E',        .dest = USER3,         .act1 = wait,},
    {.when = 'e',        .dest = USER3,         .act1 = wait,},
    {.when = ANY,        .dest = ERROR,         .act1 = unexpected,},
   
};

static const struct parser_state_transition ST_USER3[] =  {
    {.when = 'R',        .dest = USER4,         .act1 = wait,},
    {.when = 'r',        .dest = USER4,         .act1 = wait,},
    {.when = ANY,        .dest = ERROR,         .act1 = unexpected,},
   
};
static const struct parser_state_transition ST_USER4[] =  {
    {.when = ' ',        .dest = USER_VALUE,         .act1 = wait,},
    {.when = ANY,        .dest = ERROR,         .act1 = unexpected,},
   
};

static const struct parser_state_transition ST_USER_VALUE[] =  {
    {.when = '\r',        .dest = USER_VALUE_CR,         .act1 = wait,},
    {.when = ANY,        .dest = USER_VALUE,         .act1 = user_value,},
};

static const struct parser_state_transition ST_USER_VALUE_CR[] =  {
    {.when = '\n',        .dest = USER_CHECK_PLUS,         .act1 = user_value_end,},
    {.when = ANY,        .dest = ERROR,         .act1 = unexpected,},
};

static const struct parser_state_transition ST_USER_CHECK_PLUS[] =  {
    {.when = '+',        .dest = USER_CHECK_O,         .act1 = message,},
    {.when = ANY,        .dest = ERROR,         .act1 = unexpected,},
};

static const struct parser_state_transition ST_USER_CHECK_O[] =  {
    {.when = 'O',        .dest = USER_CHECK_OK,         .act1 = message,},
    {.when = ANY,        .dest = ERROR,         .act1 = unexpected,},
};

static const struct parser_state_transition ST_USER_CHECK_OK[] =  {
    {.when = 'K',        .dest = USER_ACCEPTED_MESSAGE,         .act1 = message,},
    {.when = ANY,        .dest = ERROR,         .act1 = unexpected,},
};

static const struct parser_state_transition ST_USER_ACCEPTED_MESSAGE[] =  {
    {.when = '\r',        .dest = USER_ACCEPTED_CR,         .act1 = message,},
    {.when = ANY,        .dest = USER_ACCEPTED_MESSAGE,         .act1 = message,},
};


static const struct parser_state_transition ST_USER_ACCEPTED_CR[] =  {
    {.when = '\n',        .dest = PASS0,         .act1 = message_end,},
    {.when = ANY,        .dest = ERROR,         .act1 = unexpected,},
};

static const struct parser_state_transition ST_PASS0[] =  {
    {.when = 'P',        .dest = PASS1,         .act1 = wait,},
    {.when = 'p',        .dest = PASS1,         .act1 = wait,},
    {.when = ANY,        .dest = ERROR,         .act1 = unexpected,},
};

static const struct parser_state_transition ST_PASS1[] =  {
    {.when = 'A',        .dest = PASS2,         .act1 = wait,},
    {.when = 'a',        .dest = PASS2,         .act1 = wait,},
    {.when = ANY,        .dest = ERROR,         .act1 = unexpected,},
};

static const struct parser_state_transition ST_PASS2[] =  {
    {.when = 'S',        .dest = PASS3,         .act1 = wait,},
    {.when = 's',        .dest = PASS3,         .act1 = wait,},
    {.when = ANY,        .dest = ERROR,         .act1 = unexpected,},
};

static const struct parser_state_transition ST_PASS3[] =  {
    {.when = 'S',        .dest = PASS4,         .act1 = wait,},
    {.when = 's',        .dest = PASS4,         .act1 = wait,},
    {.when = ANY,        .dest = ERROR,         .act1 = unexpected,},
};

static const struct parser_state_transition ST_PASS4[] =  {
    {.when = ' ',        .dest = PASS_VALUE,         .act1 = wait,},
    {.when = ANY,        .dest = ERROR,         .act1 = unexpected,},
};

static const struct parser_state_transition ST_PASS_VALUE[] =  {
    {.when = '\r',        .dest = PASS_VALUE_CR,         .act1 = wait,},
    {.when = ANY,        .dest = PASS_VALUE,         .act1 = pass_value,},
};

static const struct parser_state_transition ST_PASS_VALUE_CR[] =  {
    {.when = '\n',        .dest = PASS_CHECK_PLUS,         .act1 = pass_value_end,},
    {.when = ANY,        .dest = ERROR,         .act1 = unexpected,},
};

static const struct parser_state_transition ST_PASS_CHECK_PLUS[] =  {
    {.when = '+',        .dest = PASS_CHECK_O,         .act1 = wait,},
    {.when = ANY,        .dest = ERROR,         .act1 = unexpected,},
};

static const struct parser_state_transition ST_PASS_CHECK_O[] =  {
    {.when = 'O',        .dest = PASS_CHECK_OK,         .act1 = wait,},
    {.when = ANY,        .dest = ERROR,         .act1 = unexpected,},
};

static const struct parser_state_transition ST_PASS_CHECK_OK[] =  {
    {.when = 'K',        .dest = DONE,         .act1 = done,},
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
    ST_GREETING_PLUS,
    ST_GREETING_O,
    ST_GREETING_OK,
    ST_GREETING_MESSAGE,
    ST_GREETING_CR,
    ST_USER0,
    ST_USER1,
    ST_USER2,
    ST_USER3,
    ST_USER4,
    ST_USER_VALUE,
    ST_USER_VALUE_CR,
    ST_USER_CHECK_PLUS,
    ST_USER_CHECK_O,
    ST_USER_CHECK_OK,
    ST_USER_ACCEPTED_MESSAGE,
    ST_USER_ACCEPTED_CR,
    ST_PASS0,
    ST_PASS1,
    ST_PASS2,
    ST_PASS3,
    ST_PASS4,
    ST_PASS_VALUE,
    ST_PASS_VALUE_CR,
    ST_PASS_CHECK_PLUS,
    ST_PASS_CHECK_O,
    ST_PASS_CHECK_OK,
    ST_DONE,
    ST_ERROR,

};

#define N(x) (sizeof(x)/sizeof((x)[0]))

static const size_t states_n [] = {
    N(ST_GREETING_PLUS),
    N(ST_GREETING_O),
    N(ST_GREETING_OK),
    N(ST_GREETING_MESSAGE),
    N(ST_GREETING_CR),
    N(ST_USER0),
    N(ST_USER1),
    N(ST_USER2),
    N(ST_USER3),
    N(ST_USER4),
    N(ST_USER_VALUE),
    N(ST_USER_VALUE_CR),
    N(ST_USER_CHECK_PLUS),
    N(ST_USER_CHECK_O),
    N(ST_USER_CHECK_OK),
    N(ST_USER_ACCEPTED_MESSAGE),
    N(ST_USER_ACCEPTED_CR),
    N(ST_PASS0),
    N(ST_PASS1),
    N(ST_PASS2),
    N(ST_PASS3),
    N(ST_PASS4),
    N(ST_PASS_VALUE),
    N(ST_PASS_CHECK_PLUS),
    N(ST_PASS_CHECK_O),
    N(ST_PASS_CHECK_OK),
    N(ST_DONE),
    N(ST_ERROR),
};

static struct parser_definition definition = {
    .states_count = N(states),
    .states       = states,
    .states_n     = states_n,
    .start_state  = GREETING_PLUS,
};

const struct parser_definition * pop3_disector_parser_definition(void){
    return &definition;
}




void pop3_disector_init(struct pop3_disector *disector,struct log_data* log_data){
    assert(disector != NULL && log_data != NULL);
    disector->parser = parser_init(init_char_class(),pop3_disector_parser_definition());
    if(disector->parser == NULL){
        abort();
    }
    disector->log_data = log_data;
}

static void pop3_disector_reset(struct pop3_disector*disector){
    parser_reset(disector->parser);
    disector->user_counter = 0;
    disector->pass_counter = 0;
    disector->message_counter = 0;
}

static void parse_done(struct pop3_disector*disector){
    disector->log_data->user = disector->user;
    disector->log_data->password = disector->password;
    disector->log_data->protocol = POP3;
    register_password(disector->log_data);
    pop3_disector_reset(disector);
}

static void process_event(const struct parser_event *e,char c,struct pop3_disector*disector){
    switch (e->type)
    {
    case POP3_MESSAGE:

        disector->message_counter++;
        if(disector->message_counter > MAX_MESSAGE_LENGTH){
            pop3_disector_reset(disector);
        }
        break;
    case POP3_MESSAGE_END:
           
        disector->message_counter = 0;
        break;  
    case POP3_USER_VALUE:
        if(disector->user_counter >= MAX_USER_LENGTH-1){
            pop3_disector_reset(disector);
        }
        disector->user[disector->user_counter++] = c;
       
        break;
    case POP3_USER_VALUE_END:

        disector->user[disector->user_counter] = '\0';
     
        break;
    case POP3_PASS_VALUE:
          
        if(disector->pass_counter >= MAX_PASSWORD_LENGTH-1){
            pop3_disector_reset(disector);
        }
        disector->password[disector->pass_counter++] = c;
     
        break;
    case POP3_PASS_VALUE_END:

        disector->password[disector->pass_counter++] = '\0';
  
        break;
    case POP3_DONE:
     
        parse_done(disector);
        break;
    case POP3_UNEXPECTED:
        pop3_disector_reset(disector);

        break;
    case POP3_WAIT:
        /* nada */
        break;       
    default:
        break;
    }
}

void pop3_disector_consume(struct pop3_disector *disector, buffer *b){

    assert(disector != NULL && b != NULL);
    const struct parser_event *e;
    size_t nBytes;
    uint8_t* readPtr = buffer_read_ptr(b,&nBytes);
    uint8_t c;

    printf("pop3 consume\n");
    for (unsigned i = 0; i < nBytes;i++){
        c = readPtr[i];
        e = parser_feed(disector->parser, c);
        do{
            process_event(e,(char)c,disector);
            e = e->next;
        }while(e != NULL);
    }
}

