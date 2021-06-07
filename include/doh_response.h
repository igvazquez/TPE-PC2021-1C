
#ifndef MASTER_DNS_RESPONSE_H
#define MASTER_DNS_RESPONSE_H

#include <netinet/in.h>
#include <arpa/inet.h>
enum ip_type{
    IPV4= 0,
    IPV6
};


typedef struct address_resolve_info{
    int qty; //cant d ips en el storage
    struct sockaddr_storage * storage;
    enum ip_type type;

}address_resolve_info;
#endif