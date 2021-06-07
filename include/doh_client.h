#ifndef DOH__CLIENT__H
#define DOH__CLIENT__H

#include "../include/buffer.h"
#include "../include/selector.h"
#include "../include/args.h"


#include "../include/dns.h"

#define MAX_BUFFER_SIZE 1024 //TODO Alcanza?






typedef struct address_resolve_info{
    int qty; //cant d ips en el storage
    struct sockaddr_storage * storage;
    enum ip_type type;

}address_resolve_info;

enum parse_response_state {
    waiting_crlf,
    version,
    status_code,
    status_msg,
    waiting_header_content,
    waiting_header_type,
    waiting_header_type_value,
    waiting_header_length,
    waiting_header_length_value,
    waiting_instant_line_break,
    waiting_end_of_header,
    reading_data,
    error,
    finished
};

typedef struct doh_response {
    dns_response dns_response_parsed;
    uint8_t  * dns_response;
    int content_length;
    enum parse_response_state current_state;
    int state_bytes_read;
    int line_index;
    char is_dns_message;

}doh_response;

typedef struct doh {

    uint8_t data[MAX_BUFFER_SIZE];
    buffer buffer;
    char * FQDN;
    int socket;
    int client_socket;
    struct doh_args server_info;
    address_resolve_info *  resolve_info;
}doh;


int resolve (char *fqdn, fd_selector selector ,int request_socket,  address_resolve_info * address_resolve_info);



#endif
