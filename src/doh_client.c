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

void doh_kill(struct selector_key *key);
void doh_read(struct selector_key *key);
void doh_write(struct selector_key *key);
void doh_block(struct selector_key *key);
void doh_close(struct selector_key * key);
fd_handler handler = {
    .handle_close = doh_close,
    .handle_write = doh_write,
    .handle_read =  doh_read,
};

int init(doh * doh, char * fqdn){
    buffer_init(&doh->buffer,N(doh->data),doh->data);
    doh->FQDN = fqdn;
    doh->server_info = get_doh_info();
    printf("resolve init\n");


    return 1;
}


void doh_close(struct selector_key * key){
    free(key->data);
}

int resolve (char *fqdn, fd_selector selector, int request_socket, address_resolve_info * resolve_info){

    doh * doh = malloc(sizeof(struct doh));
    if (doh == NULL)
        return -1;

    doh->resolve_info = resolve_info;

    if(init(doh,fqdn)==-1) {
        goto finally;
    }

    int fd = socket(AF_INET,SOCK_STREAM,0);
    if(fd ==-1)
        return -1;
    

    //no bloqueante
    int aux = selector_fd_set_nio(fd);
    if(aux==-1)
        return -1;
    
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(doh->server_info.port);
    
    if(inet_pton(addr.sin_family, doh->server_info.ip, &addr.sin_addr) <= 0){
        goto finally;
    } 

    doh->socket = fd;
    doh->client_socket = request_socket;
    aux = connect(fd,(const struct sockaddr * ) &addr,sizeof(addr));

    if(aux ==-1){
        //Como es bloqueante falla, veo  q tiene errno
        if (errno == EINPROGRESS){
            //nos registramos en el selector para escribir la request
            selector_status status = selector_register(selector,fd,&handler,OP_WRITE,doh);
            if(status != SELECTOR_SUCCESS)
                goto finally;
            
        
        }
        else
            goto finally;
    }


    return 1;

    finally:
        free(doh);
        return -1;
    
    

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
    printf("termine de eat bytes\n");

    //memset(doh->resolve_info->storage, 0, sizeof(struct sockaddr_storage));
    doh->resolve_info->qty = 0;
    printf("llamo parse_answer\n");
    doh_response->dns_response_parsed = *parse_answer(doh_response->dns_response,doh_response->content_length,&doh->resolve_info->storage, &doh->resolve_info->qty);


}

void doh_read(struct selector_key * key){
    printf("doh_read\n");
    doh * current_doh = (doh*) key->data;

    doh_response response ;

    size_t nbyte = 0;
    uint8_t  * aux = buffer_write_ptr(&current_doh->buffer,&nbyte);

    //leemos del socket doh
    int r_bytes = recv(current_doh->socket,aux,nbyte,0);
    printf("lei %d bytes\n", r_bytes);
    if (r_bytes > 0 ){
        buffer_write_adv(&current_doh->buffer,r_bytes);
        printf("get response\n");
        get_response(current_doh,&response);
            char buff[60];
            sockaddr_to_human(buff,60,(const struct sockaddr*)current_doh->resolve_info->storage);
            printf("2 dns storage = %s\n", buff);
        if (response.current_state == finished){
            printf("get response termino\n");
            printf("storage dir: %p\n", current_doh->resolve_info->storage);
            if(selector_set_interest(key->s,current_doh->client_socket, OP_WRITE) != SELECTOR_SUCCESS)
                goto finally;

            doh_kill(key);
        }else if(response.current_state == error)
            goto finally;

        return;
    }
    finally:
    selector_set_interest(key->s,current_doh->client_socket,OP_WRITE);
   // free(current_doh->resolve_info->storage);
    doh_kill(key);


}



void doh_block(struct selector_key * key){

}
void doh_kill(struct selector_key * key){
    doh * current_doh = (doh*) key->data;

    //nos salimos del selector y liberamos recursos
    if(selector_unregister_fd(key->s,current_doh->socket))
        abort();
    close(current_doh->socket);
    //frees?

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

    http_req[http_req_len] = 0;
    *req_len = http_req_len +1 ;

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
            printf("conexion del DOH correcta\n");
            size_t nbytes = 0;
            int req_len = doh_request(current_doh);
            if (req_len == EXIT_FAILURE)
                goto finally;

            uint8_t * request = buffer_read_ptr(&current_doh->buffer,&nbytes);
            ssize_t bytes_sent = send(key->fd,request,nbytes, MSG_NOSIGNAL);
            if (bytes_sent == -1)
                goto finally;

            //queremos leer la rta del doh server ahora
            buffer_read_adv(&current_doh->buffer,bytes_sent);

            if(!buffer_can_read(&current_doh->buffer)){

                printf("Escribi toda la request\n");
                if (selector_set_interest_key(key, OP_READ) != SELECTOR_SUCCESS)
                    goto finally;

            }


            return;
        }
    }

    finally:
        doh_kill(key);

}

