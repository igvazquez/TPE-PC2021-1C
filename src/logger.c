#include <string.h>
#include <stdio.h>
#include "../include/logger.h"
#include "../include/stdoutwrite.h"




static const char * get_orig_address_string(struct sockaddr_storage address,char *ret,int length){
    if(address.ss_family == AF_INET){
        return inet_ntop(address.ss_family, &(((struct sockaddr_in *)&address)->sin_addr), ret, length);

    }
    else{
        return inet_ntop(address.ss_family, &(((struct sockaddr_in6 *)&address)->sin6_addr), ret, length);
    }
}

static char* get_dest_address_string(union dest_address address, int type){
    char *adrress = NULL; 
    switch (type){
    case ipv4_addr_t:
        adrress = (char *)malloc(INET_ADDRSTRLEN * sizeof(char));
        inet_ntop(AF_INET,adrress.ipv4.sin_addr, adrress, INET_ADDRSTRLEN);
        break;
    case ipv6_addr_t:
        adrress = (char *)malloc(INET6_ADDRSTRLEN * sizeof(char));
        inet_ntop(AF_INET6,adrress.ipv6.sin6_addr, adrress, INET6_ADDRSTRLEN);
        break;
    case domain_addr_t:
        adrress = (char *)malloc((strlen(adrress.domain)+1) * sizeof(char));
        strcpy(adrress,adrress.domain);
        break;
    }
    return adrress;
}

static void curr_time_string(char * date){
    time_t t = time(NULL);
    struct tm *timeptr = localtime(&t);
    strftime(date,DATE_SIZE,"%Y-%m-%dT%TZ",timeptr);
}

static char* get_protocol_string(int protocol_type){
    char * protocol;
    switch (protocol_type){
        case HTTP:
            protocol = "http";
            break;
        case POP3:
            protocol = "pop3";
            break;
    }
    return protocol;
}

static in_port_t address_port(struct sockaddr_storage address){
    return address.ss_family == AF_INET ? ((struct sockaddr_in*)&address)->sin_port : ((struct sockaddr_in6*)&address)->sin6_port;
}

static void logger(struct log_data *data, char log_type) {
    char date[DATE_SIZE];
    curr_time_string(date);
    char *print = NULL;
    size_t count;
    struct writer* writer_data = get_writer_data();
    uint8_t * ptr = buffer_write_ptr(&writer_data->wb,&count);
    int n = 0;
    if(log_type == 'A') {
        int length = data->orig_addr.ss_family == AF_INET ? INET_ADDRSTRLEN : INET6_ADDRSTRLEN;
        char orig_address[length];
        get_orig_address_string(data->orig_addr, orig_address ,length);
        print = "[%s]\t%s\tA\t%s\t%u\t%s\t%u\tstatus=%d\n";
        n = snprintf((char*)ptr,count,print, date, log_type, orig_address, ntohs(data->orig_port), data->method, data->target, data->status);
    }
    else if(log_type == 'P') {
        char * dest_address = get_dest_address_string(data->dest_addr, data->type);
        char * protocol = get_protocol_string(data->protocol);
        print = "[%s]\t%s\tP\t%s\t%s\t%u\t%s\t%s\n";
        n = snprintf((char*)ptr,count,print, date, log_type, protocol, dest_address, ntohs(data->dest_port), data->user, data->password);
        free(dest_address);
    }
    if ((unsigned)n > count){
        buffer_write_adv(&writer_data->wb,count);
    }
    else{
        buffer_write_adv(&writer_data->wb,n);
    }
    selector_set_interest(writer_data->selector,1, OP_WRITE);
}

void logger_access(struct log_data *data){
    logger(data, 'A');
}

void logger_passwords(struct log_data *data) {
    logger(data, 'P');
}