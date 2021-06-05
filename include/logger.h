#ifndef LOGGER_H
#define LOGGER_H
#include <sys/types.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "../include/request_message.h"
#include "../include/selector.h"
#include "../include/request_line.h"

#define DATE_SIZE 21

enum protocol {
    HTTP = 0,
    POP3,
};

struct log_data {
    enum request_line_addr_type type;

    //Access
    struct sockaddr_storage orig_addr;
    in_port_t orig_port;
    uint8_t method;
    char * target;
    char* status;
    
    //Passwords
    enum protocol protocol;
    union dest_address dest_addr;
    in_port_t dest_port;
    char *user;
    char *password;
    
};

void logger_access(struct log_data *data);
void logger_passwords(struct log_data *data);

#endif 