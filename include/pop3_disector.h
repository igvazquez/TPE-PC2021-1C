#ifndef POP3_DISECTOR_H
#define POP3_DISECTOR_H
#include "../include/register_log.h"
#include "../include/buffer.h"

#define MAX_USER_LENGTH 512 // no lo encontre en el RFC
#define MAX_PASSWORD_LENGTH 512 // no lo encontre en el RFC
#define MAX_MESSAGE_LENGTH 512 
enum pop3_disector_event_type
{
    POP3_MESSAGE,
    POP3_MESSAGE_END,
    POP3_USER_VALUE,
    POP3_USER_VALUE_END,
    POP3_PASS_VALUE,
    POP3_PASS_VALUE_END,
    POP3_DONE,
    POP3_UNEXPECTED,
    POP3_WAIT
};

struct pop3_disector{
    struct parser* parser; 
    struct log_data *log_data;
    char user[MAX_USER_LENGTH + 1];
    unsigned user_counter;
    char password[MAX_PASSWORD_LENGTH + 1];
    unsigned pass_counter;
    unsigned message_counter; // sirve para delimitar cuanto dura un mensaje de POP3 y para no quedarme en un mismo estado infinitamente
};


void pop3_disector_consume(struct pop3_disector *disector, buffer *b);
void pop3_disector_init(struct pop3_disector *disector,struct log_data* log_data);

#endif