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

__attribute__((unused)) static const char *protocol_str[] = {"HTTP", "POP3"};

struct log_info {
    uint8_t method;
    enum selector_status status;
    enum request_line_addr_type atyp;
    struct sockaddr_storage client_addr;
    union host dest_addr;
    in_port_t origin_port;
    char * target;
    
    char *user;
    char *password;
    enum protocol protocol;
    in_port_t dest_port;
};

void log_access(struct log_info *info);
void log_passwords(struct log_info *info);

#endif 