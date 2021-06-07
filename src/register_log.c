#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <arpa/inet.h>
#include "../include/register_log.h"
#include "../include/stdout_writer.h"
#include "../include/netutils.h"
#include "../include/buffer.h"

#define MAX_PORT_SIZE 5 // El puerto maximo es  65,535

void set_address_string(struct sockaddr_storage address,char *buff,int addr_length){

    switch(address.ss_family){
        case AF_INET:
         
            if (inet_ntop(AF_INET, &(((struct sockaddr_in *)&address)->sin_addr), buff, addr_length) == 0) {
                strncpy(buff, "unknown ip", addr_length);
                buff[addr_length - 1] = 0;
               
            }     
            break;

        case AF_INET6:
            
            if (inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)&address)->sin6_addr), buff, addr_length) == 0) {
                strncpy(buff, "unknown ip", addr_length);
                buff[addr_length - 1] = 0;
        
            } 
            break;
        
    }

}



char* get_origin_string(union host_addr origin_addr,enum addr_type type,in_port_t origin_port){
    char *address = NULL;
    size_t address_len;
    switch (type){  
    case ipv4_addr_t:
    
        address_len = INET_ADDRSTRLEN + MAX_PORT_SIZE + 2;
        address = (char *)calloc(1,address_len);
        if(address == NULL){
            return NULL;
        }
        sockaddr_to_human(address,address_len,(const struct sockaddr*)&origin_addr.ipv4);
     
        break;
    case ipv6_addr_t:
  
        address_len = INET6_ADDRSTRLEN  + MAX_PORT_SIZE + 4;
        address = (char *)calloc(1,address_len);
        if(address == NULL){
            return NULL;
        }
        char ipv6[INET6_ADDRSTRLEN];
        const struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&origin_addr.ipv6;
        if (inet_ntop(addr6->sin6_family, &(addr6->sin6_addr),  ipv6, INET6_ADDRSTRLEN) == 0) {
            strncpy(address, "unknown ip", INET6_ADDRSTRLEN);
            address[INET6_ADDRSTRLEN - 1] = 0;
        }
        printf("ipv6 origin addres: %s\n", address);

        if(-1 == sprintf(address,"[%s]:%d",ipv6,ntohs(origin_port))){
            abort();
        }
        printf("despues del sprintf: %s\n", address);
        break;
    case domain_addr_t:
  
        address_len = MAX_FQDN_LENGTH  + MAX_PORT_SIZE + 2;
        address = (char *)calloc(1,address_len);
        if(address == NULL){
            return NULL;
        }
        if(-1 == sprintf(address,"%s:%d",origin_addr.domain,ntohs(origin_port))){
            abort();
        }
        break;
    }


    return address;
}

void get_current_date_string(char * date){
    time_t t = time(NULL);
    struct tm *timeptr = localtime(&t);
    strftime(date,MAX_DATE_LENGTH+1,"%Y-%m-%dT%TZ",timeptr);
}

static char* get_protocol_string(enum protocol protocol){

    switch (protocol){
        case HTTP:
            return "HTTP";
            break;
        case POP3:
            return "POP3";
            break;
    }
    return NULL;
}

static in_port_t get_address_port(struct sockaddr_storage address){
    return address.ss_family == AF_INET ? ((struct sockaddr_in*)&address)->sin_port : ((struct sockaddr_in6*)&address)->sin6_port;
}

static void log_register(struct log_data *log_data, char reg_type) {
    char *format = NULL;
    size_t wBytes;
    struct stdout_writer* writer_data = get_stdout_writer_data();
    char buffer[100];
    uint8_t * write_ptr = buffer_write_ptr(&writer_data->wb,&wBytes);
    int n = 0;
    if(reg_type == 'A'){
            int client_addr_length = log_data->client_addr->ss_family == AF_INET ? INET_ADDRSTRLEN : INET6_ADDRSTRLEN;

            char client_address_str[client_addr_length];
            set_address_string(*log_data->client_addr, client_address_str ,client_addr_length);
            char* format = "%s\tA\t%s\t%d\t%s\thttp://%s%s\t%s\n";
            char *origin_form = log_data->origin_form;
            n = snprintf(buffer,100,format, log_data->date,client_address_str, ntohs(get_address_port(*log_data->client_addr)), log_data->method, get_origin_string(log_data->origin_addr,log_data->origin_addr_type,log_data->origin_port),origin_form, log_data->status_code);
            
    }else if(reg_type == 'P'){
        char *origin_addr = get_origin_string(log_data->origin_addr, log_data->origin_addr_type, log_data->origin_port);
        char *host;
        char *port;

        if(origin_addr != NULL){
            host = strtok(origin_addr, ":");
            port = strtok(NULL, ":");
        }else{
            host = "UNKOWN";
            port = "UNKOWN";
        }
    
        format = "%s\tP\t%s\t%s\t%s\t%s\t%s\n";
        n = snprintf(buffer,100,format, log_data->date,get_protocol_string(log_data->protocol),host, port, log_data->user, log_data->password);
        free(origin_addr);
    }else{
        return;
    }
    printf("%s",buffer);
    /*  if ((unsigned)n > wBytes){
        buffer_write_adv(&writer_data->wb,wBytes);
    }
    else{
        buffer_write_adv(&writer_data->wb,n);
    }
   

    selector_set_interest(*writer_data->selector,1, OP_WRITE);*/
}

void register_access(struct log_data *log_data){
    log_register(log_data, 'A');
}

void register_password(struct log_data *log_data) {
    log_register(log_data, 'P');
}