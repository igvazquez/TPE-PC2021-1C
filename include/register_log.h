#ifndef REGISTER_LOG_H
#define REGISTER_LOG_H
#include <sys/types.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "../include/request_message.h"
#include "../include/selector.h"
#include "../include/request_line.h"
#include "../include/error_responses.h"

#define MAX_DATE_LENGTH 21
#define MAX_STATUS_LENGTH 4 

enum protocol {
    HTTP = 0,
    POP3,
};


struct log_data {

    //Access
    struct sockaddr_storage client_addr;
    in_port_t client_port;
    char method[MAX_METHOD_LENGTH+1];
    union host_addr origin_addr;
    enum addr_type origin_addr_type;
    in_port_t origin_port;
    char origin_form[MAX_ORIGIN_FORM+1];
    status_code status;

    //Passwords
    char *user;
    char *password;
    enum protocol protocol;
};



void register_access(struct log_data * data);
void register_password(struct log_data *data);

#endif 