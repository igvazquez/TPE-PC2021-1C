#ifndef DNS__H
#define DNS__H
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>


enum ip_type{
    IPV4= 0,
    IPV6
};

enum RESPONSE_CODE {
    NO_ERROR,
    FORMAT_ERROR,
    SERVER_FAILURE,
    NAME_ERROR,
    NOT_IMPLEMENTED,
    REFUSED
};

typedef struct _DNS_HEADER {
    unsigned short id;       // identification number

    unsigned char query_or_response :1;     // query/response flag
    unsigned char opcode :4; // purpose of message
    unsigned char authoritative_answer :1;     // authoritative answer
    unsigned char truncated_message :1;     // truncated message
    unsigned char recursion_desired :1;     // recursion desired


    unsigned char recursion_available :1;     // recursion available
    unsigned char z_reserved :1;      // its z! reserved
    unsigned char authenticated_data :1;     // authenticated data
    unsigned char checking_disabled :1;     // checking disabled
    unsigned char response_code :4;  // response code

    unsigned short q_count;  // number of question entries
    unsigned short ans_count; // number of answer entries
    unsigned short auth_count; // number of authority entries
    unsigned short add_count; // number of resource entries

} DNS_HEADER;

typedef struct dns_response {
    /*enum RESPONSE_CODE response_code;
    short number_answers*/

    DNS_HEADER header;
} dns_response;

void generate_query(char * fqdn,unsigned  char * result, int * dns_query_size, enum ip_type ip_type);



dns_response * parse_answer(unsigned char * response, size_t bytes, struct sockaddr_storage * storage, int * qty);


#endif
