#include <string.h>
#include <stdio.h>
#include "../include/logger.h"
#include "../include/stdoutwrite.h"

static void date_to_string(char * date){
    
    time_t timer = time(NULL);
    struct tm * tm = gmtime(&timer);
    strftime(date,DATE_SIZE,"%Y-%m-%dT%TZ",tm);
}


static const char * ip_to_string(struct sockaddr_storage addr,char *ret,int length){
    if(addr.ss_family == AF_INET){
        return inet_ntop(addr.ss_family, &(((struct sockaddr_in *)&addr)->sin_addr), ret, length);

    }
    else{
        return inet_ntop(addr.ss_family, &(((struct sockaddr_in6 *)&addr)->sin6_addr), ret, length);
    }
}

static in_port_t addr_port(struct sockaddr_storage addr){
    return addr.ss_family == AF_INET ? ((struct sockaddr_in*)&addr)->sin_port : ((struct sockaddr_in6*)&addr)->sin6_port;
}

static char* dest_addr_to_string(struct log_info *info){
    char *ip = NULL; 
    switch (info->atyp)
    {
    case ipv4_addr_t:
        ip = (char *)malloc(INET_ADDRSTRLEN * sizeof(char));
        inet_ntop(AF_INET,&info->dest_addr.ipv4.sin_addr, ip, INET_ADDRSTRLEN);
        break;
    case ipv6_addr_t:
        ip = (char *)malloc(INET6_ADDRSTRLEN * sizeof(char));
        inet_ntop(AF_INET6,&info->dest_addr.ipv6.sin6_addr, ip, INET6_ADDRSTRLEN);
        break;
    case domain_addr_t:
        ip = (char *)malloc((strlen(info->dest_addr.domain)+1) * sizeof(char));
        strcpy(ip,info->dest_addr.domain);
        break;
    }
    return ip;
}

static void print_log(struct log_info *info, char type) {
    char date[DATE_SIZE];
    date_to_string(date);
    int length = info->client_addr.ss_family == AF_INET ? INET_ADDRSTRLEN : INET6_ADDRSTRLEN;
    char address_orig[length];
    ip_to_string(info->client_addr, address_orig ,length);
    char * dest_ip = dest_addr_to_string(info);
    char *print = NULL;
    size_t count;
    struct writer* writer_data = get_writer_data();
    uint8_t * ptr = buffer_write_ptr(&writer_data->wb,&count);
    int n = 0;
    if(type == 'A') {
        print = "[%s]\t%s\tA\t%s\t%u\t%s\t%u\tstatus=%d\n";
        n = snprintf((char*)ptr,count,print, date, type, address_orig, ntohs(info->orig_port), info->method, info->target, info->status);
    }
    else if(type == 'P') {
        print = "[%s]\t%s\tP\t%s\t%s\t%u\t%s\t%s\n";
        n = snprintf((char*)ptr,count,print, date, type, protocol_str[info->protocol], dest_ip, ntohs(info->dest_port), info->user, info->password);
    }
    if ((unsigned)n > count){
        buffer_write_adv(&writer_data->wb,count);
    }
    else{
        buffer_write_adv(&writer_data->wb,n);
    }
    selector_set_interest(writer_data->selector,1, OP_WRITE);
    free(dest_ip);
}

void log_access(struct log_info *info){
    print_log(info, 'A');
}

void log_passwords(struct log_info *info) {
    print_log(info, 'P');
}