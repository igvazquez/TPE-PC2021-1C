#include "../include/doh_client.h"
#include "../include/selector.h"
#include "../include/dns.h"
#include "../include/base64_utils.h"
#include "../include/parse_doh_http_response.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include "../include/netutils.h"

#define N(x) (sizeof(x)/sizeof((x)[0]))
#define DOH_ATTACHMENT(key) ( (struct doh*)(key)->data)

static void close_client(struct selector_key *key);

void doh_kill(struct selector_key *key);
void doh_read(struct selector_key *key);
void doh_write(struct selector_key *key);
void doh_close(struct selector_key * key);
fd_handler handler = {
    .handle_close = doh_close,
    .handle_write = doh_write,
    .handle_read =  doh_read,
};
void doh_init(doh * doh, char * fqdn){
    buffer_init(&doh->buffer,N(doh->data),doh->data);
    doh->FQDN = fqdn;
    doh->server_info = get_doh_info();
}
void doh_close(struct selector_key * key){   
    free((void*)DOH_ATTACHMENT(key));
}



resolve_status resolve (char *fqdn, fd_selector selector, int request_socket, address_resolve_info * resolve_info){


    int fd = socket(AF_INET,SOCK_STREAM,0);
    if(fd ==-1){
        goto finally;
    }   
    //no bloqueante
    if(selector_fd_set_nio(fd) == -1){

        goto finally;
    }
    doh * doh = malloc(sizeof(struct doh));
    if (doh == NULL){
        goto finally;
    }
    doh->resolve_info = resolve_info;
    doh_init(doh,fqdn);  

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(doh->server_info.port);
    
    if(inet_pton(addr.sin_family, doh->server_info.ip, &addr.sin_addr) <= 0){
        goto finally;
    } 

    doh->socket = fd;
    doh->client_socket = request_socket;

    if( connect(fd,(const struct sockaddr * ) &addr,sizeof(addr)) ==-1){
        //Como es bloqueante falla, veo  q tiene errno
        if (errno == EINPROGRESS){
            //nos registramos en el selector para escribir la request
            if( selector_register(selector,fd,&handler,OP_WRITE,doh) != SELECTOR_SUCCESS)
                goto finally;
            return RESOLVE_OK;
        }else{
            goto finally;
        }
  
    }
finally:
    doh->resolve_info->status = RESOLVE_ERROR;
    if(fd != -1){
        close(fd);
    }
    if(doh != NULL){
        free(doh);
    }

    return RESOLVE_ERROR;
}


void get_response(doh * doh , doh_response * doh_response){


    buffer * b = &(doh->buffer);
    enum parse_response_state state = version;


    doh_response->current_state = version;
    doh_response->state_bytes_read = 0;
    doh_response->line_index = 0;
    doh_response->content_length = -1;
    doh_response->is_dns_message = 0;


    while (buffer_can_read(b) && state != finished && state != error){
        unsigned char byte = buffer_read(b);
        eat_byte(doh_response,byte);
        state = doh_response->current_state;
    }
    doh_response->dns_response_parsed = *parse_answer(doh_response->dns_response,doh_response->content_length,doh->resolve_info);


}

void doh_read(struct selector_key * key){
    doh * current_doh = (doh*) key->data;
    doh_response response ;
    size_t nbyte = 0;
    uint8_t  * aux = buffer_write_ptr(&current_doh->buffer,&nbyte);

    //leemos del socket doh
    int r_bytes = recv(current_doh->socket,aux,nbyte,0);
    if (r_bytes > 0 ){
        buffer_write_adv(&current_doh->buffer,r_bytes);
        get_response(current_doh,&response);
            char buff[60];
            sockaddr_to_human(buff,60,(const struct sockaddr*)current_doh->resolve_info->storage);
        if (response.current_state == finished){
            current_doh->resolve_info->status = RESOLVE_OK;
            free(response.dns_response);
            free(&response.dns_response_parsed);
          
            if(selector_set_interest(key->s,current_doh->client_socket, OP_WRITE) != SELECTOR_SUCCESS){
                close_client(key);
            }
            doh_kill(key);
            return;
        }else if(response.current_state == error){
               goto finally;
        }
         
    }else{

        goto finally;
    }
    finally:
        current_doh->resolve_info->status = RESOLVE_ERROR;
        free(response.dns_response);
        free(&response.dns_response_parsed);
        doh_kill(key);
        if(selector_set_interest(key->s,current_doh->client_socket, OP_WRITE) != SELECTOR_SUCCESS){
            close_client(key);
        }


}

void doh_kill(struct selector_key * key){
    doh * current_doh = (doh*) key->data;
    //nos salimos del selector y liberamos recursos
    if(selector_unregister_fd(key->s,current_doh->socket) == -1){
        abort();
    }
  
}

//arma la query en http con metodo GET
char * create_doh_get_req (doh * doh, size_t * req_len){
    char * METHOD = "GET ";
    char * VERSION = " HTTP/1.0\r\n"; //no tenemos pq usar la misma q el proxy, 1.0 no tiene keep-alive
    char * ACCEPT_HEADER = "Accept: application/dns-message\r\n";
    char * PATH = doh->server_info.path;
    char * HOST_HEADER = "Host: ";
    char * HOST = doh->server_info.host;
    char * QUERY = doh->server_info.query;
    char * END = "\r\n\r\n";

    //TODO CAMBIAME
    unsigned char dns_query [400];
    int dns_query_size = 0;
    generate_query(doh->FQDN,dns_query,&dns_query_size,doh->resolve_info->type);
    size_t encoded_query_size = 0;
    char * QUERY_ENCODED = base64url_encode(dns_query,dns_query_size,&encoded_query_size);

    int tokens_qty = 9;

    char * tokens [] = {METHOD, PATH, QUERY, QUERY_ENCODED, VERSION, ACCEPT_HEADER, HOST_HEADER,HOST,END};
    size_t sizes [tokens_qty];
    size_t http_req_len = 0;
    for (int j = 0; j<tokens_qty;j++){
        size_t size;
        if(j == 3)
            size = encoded_query_size;

        else
            size = strlen(tokens[j]);
        http_req_len += size;
        sizes[j] = size;
    }

    char * http_req = (char*) malloc(http_req_len + 1);
    if(http_req == NULL)
        //errorr
        return NULL;

    size_t offset =0;
    int i;
    for (i = 0;i < tokens_qty; i++){

        memcpy(http_req + offset,tokens[i],sizes[i]);
        offset += sizes[i];
    }
    free(QUERY_ENCODED);
    http_req[http_req_len] = 0;
    *req_len = http_req_len +1 ;

    for(int i = 0;i < http_req_len +1;i++)
        putchar(http_req[i]);
    return http_req;
}

int doh_request(doh * doh){
    size_t nbytes = 0;
    uint8_t  * w_buffer = buffer_write_ptr(&doh->buffer,&nbytes);
    size_t req_len = 0;
    char  * req = create_doh_get_req(doh,&req_len);

    //escribimos al buffer de doh
    if (nbytes < req_len){
        free(req);
        return EXIT_FAILURE;
    }
    memcpy(w_buffer,req,req_len);

    buffer_write_adv(&doh->buffer,req_len);

    free(req);

    return req_len;


}

void doh_write (struct selector_key * key){

    doh * current_doh = DOH_ATTACHMENT(key);

    int socket_error;
    socklen_t socket_error_len = sizeof(socket_error);
    if(getsockopt(current_doh->socket,SOL_SOCKET, SO_ERROR, &socket_error, &socket_error_len) == 0){
        if(socket_error!=0)
            goto finally;
        else{
            size_t nbytes = 0;
            int req_len = doh_request(current_doh);
            if (req_len == EXIT_FAILURE)
                goto finally;

            uint8_t * request = buffer_read_ptr(&current_doh->buffer,&nbytes);
            ssize_t bytes_sent = send(key->fd,request,nbytes, MSG_NOSIGNAL);
            if (bytes_sent <=0)
                goto finally;
            //queremos leer la rta del doh server ahora
            buffer_read_adv(&current_doh->buffer,bytes_sent);
            if(!buffer_can_read(&current_doh->buffer)){
                if (selector_set_interest_key(key, OP_READ) != SELECTOR_SUCCESS)
                    goto finally;

            }else{
                //no pude enviar toda la request, por ahora cancelamos la conexión
                goto finally;
            }

            return;
        }
    }

    finally:
        current_doh->resolve_info->status = RESOLVE_ERROR;
        doh_kill(key);
        if(selector_set_interest(key->s,current_doh->client_socket, OP_WRITE) != SELECTOR_SUCCESS){
            //si falla entonces cierro desde aca la conexión con el cliente
            close_client(key);
        }
            
      

}

static void close_client(struct selector_key *key){

    if(SELECTOR_SUCCESS != selector_unregister_fd(key->s, DOH_ATTACHMENT(key)->client_socket)) {
        abort();
    }
    if(close(DOH_ATTACHMENT(key)->client_socket)){
        abort();
    }
}