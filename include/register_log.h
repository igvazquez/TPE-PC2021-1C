#ifndef REGISTER_LOG_H
#define REGISTER_LOG_H
#include <sys/types.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "../include/request_message.h"
#include "../include/selector.h"
#include "../include/request_line.h"
#include "../include/response_line.h"
#include "../include/error_responses.h"

#define MAX_DATE_LENGTH 20 // Ej: 202-06-15T19:30:52Z\0


enum protocol {
    HTTP = 0,
    POP3,
};


struct log_data {
    char date[MAX_CODE_LENGTH+1];
    //Access
    struct sockaddr_storage client_addr;
    in_port_t client_port;
    char method[MAX_METHOD_LENGTH+1];
    union host_addr origin_addr;
    enum addr_type origin_addr_type;
    in_port_t origin_port;
    char origin_form[MAX_ORIGIN_FORM+1];
    char status_code[MAX_CODE_LENGTH + 1];
    

    //Passwords
    char *user;
    char *password;
    enum protocol protocol;
};

void get_current_date_string(char *date);
void register_access(struct log_data * data);
void register_password(struct log_data *data);

#endif 