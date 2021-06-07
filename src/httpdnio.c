#include "../include/httpdnio.h"
#include "../include/request_line.h"
#include "../include/request_message.h"
#include "../include/stm.h"
#include "../include/buffer.h"
#include "../include/netutils.h"
#include "../include/response_line.h"
#include "../include/error_responses.h"
#include "../include/http_disector.h"
#include "../include/pop3_disector.h"
#include "../include/register_log.h"
#include "../include/args.h"
#include "../include/doh_client.h"
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>  // malloc
#include <string.h>  // memset
#include <assert.h>  // assert
#include <errno.h>
#include <time.h>
#include <unistd.h>  // close
#include <pthread.h>
#include <arpa/inet.h>
#include <stddef.h>
#include <stdint.h>
#include <netinet/in.h>
#include <stdbool.h>

/**  tamaño del buffer de read y write **/
#define MAX_BUFF_SIZE 8*1024

#define N(x) (sizeof(x)/sizeof((x)[0]))

/** obtiene el struct (httpd *) desde la llave de selección  */
#define ATTACHMENT(key) ( (struct httpd *)(key)->data)

#define WRITE_MESSAGE_EXTRA_SPACE 64

static void httpd_read   (struct selector_key *key);
static void httpd_write  (struct selector_key *key);
static void httpd_block  (struct selector_key *key);
static void httpd_close  (struct selector_key *key);


static error_status_code errno_response(int e);

static void connecting_init(const unsigned state,struct selector_key *key);
static unsigned connecting_done(struct selector_key *key);

static void request_line_read_init(const unsigned state,struct selector_key *key);
static unsigned request_line_read(struct selector_key *key);

static unsigned request_resolve_done(struct selector_key *key);

static void request_line_write_init(const unsigned state,struct selector_key *key);
static unsigned request_line_write(struct selector_key *key);
static void request_line_write_on_departure(const unsigned state, struct selector_key *key);

static void response_line_read_init(const unsigned state,struct selector_key *key);
static unsigned response_line_read(struct selector_key *key);

static void response_line_write_init(const unsigned state,struct selector_key *key);
static void response_line_write_on_departure(const unsigned state,struct selector_key *key);
static unsigned response_line_write(struct selector_key *key);

static void request_message_init(const unsigned state, struct selector_key *key);
static unsigned request_message_write(struct selector_key *key);
static unsigned request_message_read(struct selector_key *key);
static void request_message_on_departure(const unsigned state, struct selector_key *key);

static void response_message_init(const unsigned state,struct selector_key *key);
static unsigned response_message_read(struct selector_key* key);
static unsigned response_message_write(struct selector_key* key);
static void response_message_on_departure(const unsigned state, struct selector_key *key);

static void error_init(const unsigned state,struct selector_key * key);
static unsigned error_write(struct selector_key* key);

static void copy_init(const unsigned state,struct selector_key *key);
static unsigned copy_read(struct selector_key *key);
static unsigned copy_write(struct selector_key *key);



/** maquina de estados general */
enum httpd_state {
    REQUEST_LINE_READ,
    REQUEST_RESOLVE,
    CONNECTING,
    REQUEST_LINE_WRITE,
    REQUEST_MESSAGE,
    RESPONSE_LINE_READ,
    RESPONSE_LINE_WRITE,
    RESPONSE_MESSAGE,
    COPY,
    // estados terminales
    DONE,
    ERROR,
};

////////////////////////////////////////////////////////////////////
// Definición de variables para cada estado


struct connecting_st{
    /* buffer utilizado para I/O */
    //buffer                *wb;
    int client_fd;
    int origin_fd;
    //struct connecting_parser   parser;
 
};

struct data_to_send{
    uint8_t *data_to_send;
    unsigned data_to_send_len;
    unsigned data_to_send_written;
    buffer data_to_send_buffer;
};

struct request_line_st{
    buffer *rb;
    
    struct request_line request_line_data;
    struct request_line_parser parser;
    struct data_to_send data;

    //addr resolution
    address_resolve_info resolve_info;
};

struct response_line_st {
    buffer *rb;

    struct response_line response_line_data;
    struct response_line_parser parser;
    struct data_to_send data;
};

struct request_message_st{
    buffer * rb;
    struct request_message_parser parser;
};


struct copy_st{
    /* buffer utilizado para I/O */
    buffer *rb, *wb;

    /* client_fd si soy cliente u origin_fd si soy origin */
    int fd;

    fd_interest interest;

    /* origin.copy si soy cliente o client.copy si soy origin */
    struct copy_st *copy_to;
};

/*
 * Si bien cada estado tiene su propio struct que le da un alcance
 * acotado, disponemos de la siguiente estructura para hacer una Ãºnica
 * alocaciÃ³n cuando recibimos la conexiÃ³n.
 *
 * Se utiliza un contador de referencias (references) para saber cuando debemos
 * liberarlo finalmente, y un pool para reusar alocaciones previas.
 */
struct httpd {
    /* buffers de write y read */
    uint8_t from_client_buffer_data[MAX_BUFF_SIZE],from_origin_buffer_data[MAX_BUFF_SIZE];
    buffer from_client_buffer,from_origin_buffer;

    /* maquinas de estados */
    struct state_machine stm;

   /* información del cliente */
    struct sockaddr_storage client_addr;
    socklen_t client_addr_len;
    int client_fd;
    /* estados para el client_fd */
    union {
        struct request_line_st request_line;
        struct response_line_st response_line;
        struct request_message_st request_message;
        struct copy_st copy;
    } client;

    
    /* información del server origen */
    struct sockaddr_storage origin_addr;
    socklen_t origin_addr_len;
    int origin_addr_type;

    int origin_fd;

    /* estados para el origin_fd */
    union {
        struct connecting_st connecting;
        struct request_message_st request_message;
        struct copy_st copy;
    } origin;

    struct log_data log_data;
    enum error_status_code status;
 
    /* password disectors */
    struct http_disector http_disector;
    struct pop3_disector pop3_disector;

};

/** Definición de handlers para cada estado */
static const struct state_definition client_statbl[] = {

    {
     .state = REQUEST_LINE_READ,
     .on_arrival = request_line_read_init,
     .on_read_ready = request_line_read
     },
     {
      .state = REQUEST_RESOLVE,
      .on_write_ready = request_resolve_done,
     },
    {
     .state = CONNECTING,
     .on_arrival = connecting_init,
     .on_write_ready = connecting_done
     },
    {
     .state = REQUEST_LINE_WRITE,
     .on_arrival = request_line_write_init,
     .on_write_ready = request_line_write,
     .on_departure = request_line_write_on_departure
     },
     {.state = REQUEST_MESSAGE,
        .on_arrival = request_message_init,
        .on_read_ready = request_message_read,
        .on_write_ready = request_message_write,
        .on_departure = request_message_on_departure,
     },
    {
        .state = RESPONSE_LINE_READ,
        .on_arrival = response_line_read_init,
        .on_read_ready = response_line_read
    },
    {
        .state = RESPONSE_LINE_WRITE,
        .on_arrival = response_line_write_init,
        .on_write_ready = response_line_write,
        .on_departure = response_line_write_on_departure
    },
    {
        .state = RESPONSE_MESSAGE,
        .on_arrival = response_message_init,
        .on_read_ready = response_message_read,
        .on_write_ready = response_message_write,
        .on_departure = response_message_on_departure,
     },
    {
        .state = COPY,
        .on_arrival = copy_init,
        .on_read_ready = copy_read,
        .on_write_ready = copy_write
     },
    {
        .state = DONE,
    },
    {
        .state = ERROR,
        .on_arrival = error_init,
        .on_write_ready = error_write
    }
};

static const struct fd_handler httpd_handler = {
    .handle_read   = httpd_read,
    .handle_write  = httpd_write,
    .handle_close  = httpd_close,
    .handle_block  = httpd_block,
};

///////////////////////////////////////////////////////////////////////////////
// Handlers top level de la conexión pasiva.
// son los que emiten los eventos a la maquina de estados.
static void
httpd_done(struct selector_key* key);


static void
httpd_read(struct selector_key *key) {
    struct state_machine *stm   = &(ATTACHMENT(key)->stm);
    const enum httpd_state st = stm_handler_read(stm, key);

    if(DONE == st) {
        if(ATTACHMENT(key)->origin_fd != -1){
               printf("METHOD: %s\n", ATTACHMENT(key)->log_data.method);
                if(ATTACHMENT(key)->log_data.client_addr->ss_family == AF_INET){
                    printf(" read CLIENT ES IPV4\n");
                }
               
             register_access(&ATTACHMENT(key)->log_data);
        }
        httpd_done(key);
    }
}

static void
httpd_write(struct selector_key *key) {
    printf("handler write\n");
    struct state_machine *stm   = &(ATTACHMENT(key)->stm);

    const enum httpd_state st = stm_handler_write(stm, key);

    if(DONE == st) {
        if(ATTACHMENT(key)->origin_fd != -1){
            printf("METHOD: %s\n", ATTACHMENT(key)->log_data.method);

                if(ATTACHMENT(key)->log_data.client_addr->ss_family == AF_INET){
                    printf(" write CLIENT ES IPV4\n");
                }
             register_access(&ATTACHMENT(key)->log_data);
        }
       
        httpd_done(key);
    }
}

static void
httpd_block(struct selector_key *key) {
    struct state_machine *stm   = &(ATTACHMENT(key)->stm);
    const enum httpd_state st = stm_handler_block(stm, key);

    if(DONE == st) {
        if(ATTACHMENT(key)->origin_fd != -1){


             register_access(&ATTACHMENT(key)->log_data);
        }
        httpd_done(key);
    }
}

static void
httpd_close(struct selector_key *key) {
   // socks5_destroy(ATTACHMENT(key));
}

static void
httpd_done(struct selector_key* key) {
    const int fds[] = {
        ATTACHMENT(key)->client_fd,
        ATTACHMENT(key)->origin_fd,
    };
    printf("Cierro conexión entre cliente %d y origin %d\n", fds[0], fds[1]);
    for(unsigned i = 0; i < N(fds); i++) {
        if(fds[i] != -1) {
            if(SELECTOR_SUCCESS != selector_unregister_fd(key->s, fds[i])) {
                abort();
            }
            close(fds[i]);
        }
    }
}
///////////////////////////////////////////////////////////////////////////////
// Devuelve el attachment para la nueva conexión

static struct httpd *httpd_new(int client_fd){
    struct httpd *ret =  malloc(sizeof(*ret));
    if(ret  == NULL){
        return NULL;
    }
    memset(ret, 0x00, sizeof(*ret));
    ret->stm.states = client_statbl;
    ret->stm.initial = REQUEST_LINE_READ;
    ret->stm.max_state = ERROR;
    stm_init(&(ret->stm));

    ret->client_fd = client_fd;
    ret->origin_fd = -1;

    buffer_init(&ret->from_client_buffer, N(ret->from_client_buffer_data), ret->from_client_buffer_data);
    buffer_init(&ret->from_origin_buffer, N(ret->from_origin_buffer_data), ret->from_origin_buffer_data);

    http_disector_init(&ret->http_disector,&ret->log_data);
    pop3_disector_init(&ret->pop3_disector,&ret->log_data);
    //Como default es 200 por si el cliente cierra la conexión antes de terminar de enviar la request
    strcpy(ret->log_data.status_code, "200");
    return ret;
}

static unsigned connect_to_origin(int origin_family, struct selector_key*key);

/** Intenta aceptar la nueva conexión entrante*/


void
httpd_passive_accept(struct selector_key *key) {
    struct sockaddr_storage       client_addr;
    socklen_t                     client_addr_len = sizeof(client_addr);
    struct httpd                *state           = NULL;
    printf("Aceptando conexión en socket %d\n",key->fd);
    const int client = accept(key->fd, (struct sockaddr*) &client_addr, &client_addr_len);
    // printf("1 direccion s: %p\n", key->s);
    if(client == -1) {
        goto fail;
    }
    if(selector_fd_set_nio(client) == -1) {
        goto fail;
     }
    state = httpd_new(client);
    if(state == NULL) {
        // sin un estado, nos es imposible manejaro.
        // tal vez deberiamos apagar accept() hasta que detectemos
        // que se liberÃ³ alguna conexiÃ³n.
        goto fail;
    }

    memcpy(&state->client_addr, &client_addr, client_addr_len);
    memcpy(&state->log_data.client_addr, &client_addr, client_addr_len);
    state->client_addr_len = client_addr_len;
    state->log_data.client_addr = &state->client_addr;
    
    // no quiero leer desde el cliente hasta que me conecte con el origen
   if(SELECTOR_SUCCESS != selector_register(key->s, client, &httpd_handler,
                                              OP_READ, state)) {
        goto fail;
    }

    return;

fail:
    printf("fail:\n");
    if(client != -1) {
        close(client);
    }
    free(state);
    //TODO liberar bien los recursos
    //socks5_destroy(state);
}

////////////////////////////////////////////////////////////////////////////////
// REQUEST LINE READ
////////////////////////////////////////////////////////////////////////////////

static void request_line_read_init(const unsigned state,struct selector_key *key){
    printf("request line read init\n");
    assert(state == REQUEST_LINE_READ);
    struct httpd *data = ATTACHMENT(key);
    struct request_line_st* rl = &(data->client.request_line);
    request_line_parser_init(&(rl->parser));
    rl->parser.request_line = &(data->client.request_line.request_line_data);
    rl->rb = &(data->from_origin_buffer);
}

static unsigned request_line_process(struct request_line_st *rl, struct selector_key *key);
static unsigned request_line_read(struct selector_key *key)
{
    
    struct httpd *data = ATTACHMENT(key);
    struct request_line_st* rl = &data->client.request_line;

    buffer *b = rl->rb;
    data->status = OK;
    size_t wbytes;
    uint8_t *read_buffer_ptr = buffer_write_ptr(b, &wbytes);
 
    ssize_t numBytesRead = recv(key->fd, read_buffer_ptr, wbytes,0);
    unsigned ret = REQUEST_LINE_READ;
    if (numBytesRead > 0)
    {
        buffer_write_adv(b, numBytesRead);
        bool done = request_line_parser_consume(b, &rl->parser, &data->status);
        if(done){
            if(data->status != OK){
                ret = ERROR;
            }else{
                printf("termine de parsear sin error\n");
                printf("metodo: %s\n", rl->request_line_data.method);

                switch(rl->request_line_data.request_target.host_type){
                    case ipv6_addr_t:
                        printf("ipv6 origen: %s\n", rl->parser.parsed_info.host.ipv6_buffer);
                        break;
                    case ipv4_addr_t:
                        printf("ipv4 origen: %s\n", rl->parser.parsed_info.host.domain_or_ipv4_buffer);
                        break;

                    case domain_addr_t:
                        printf("domain origen: %s\n", rl->parser.parsed_info.host.domain_or_ipv4_buffer);
                        break;
                }
                printf("puerto: %d\n", ntohs(rl->request_line_data.request_target.port));
                printf("version %d.%d\n", rl->parser.parsed_info.version_major, rl->parser.parsed_info.version_minor);
                printf("origin form: %s\n", rl->parser.parsed_info.origin_form_buffer);
                //request_line_parser_reset(&rl->parser);

                if (SELECTOR_SUCCESS != selector_set_interest(key->s, data->client_fd, OP_NOOP))
                {
                    data->status = INTERNAL_SERVER_ERROR;
                    goto finally;
                }

                //proceso la request line
                ret = request_line_process(rl,key);
            }
            //termine de consumir request line;
            
        }
    }
    else
    {
        ret = ERROR;
    }

finally:
    return data->status != OK ? ERROR : ret;
}

static unsigned request_line_process(struct request_line_st * rl,struct selector_key * key){
    unsigned ret = ERROR;
   

    struct httpd *data = ATTACHMENT(key);
    struct sockaddr_storage*origin_addr = &data->origin_addr;
    switch (rl->request_line_data.request_target.host_type)
    {
    case ipv6_addr_t:

        rl->request_line_data.request_target.host.ipv6.sin6_port =  rl->request_line_data.request_target.port;
        rl->request_line_data.request_target.host.ipv6.sin6_family = AF_INET6;
        data->origin_addr_type = AF_INET6;
        data->origin_addr_len = sizeof(rl->request_line_data.request_target.host.ipv6);
        memcpy(&data->origin_addr, &rl->request_line_data.request_target.host.ipv6,data->origin_addr_len);
        memcpy(&data->log_data.origin_addr.ipv6, &rl->request_line_data.request_target.host.ipv6, data->origin_addr_len);
        data->log_data.origin_addr_type = ipv6_addr_t;
        ret = connect_to_origin(AF_INET6, key);
        break;
    case ipv4_addr_t:

        rl->request_line_data.request_target.host.ipv4.sin_port =  rl->request_line_data.request_target.port;
        rl->request_line_data.request_target.host.ipv4.sin_family = AF_INET;
        data->origin_addr_type = AF_INET;
        data->origin_addr_len = sizeof(rl->request_line_data.request_target.host.ipv4);
        memcpy(&data->origin_addr, &rl->request_line_data.request_target.host.ipv4, data->origin_addr_len);
        memcpy(&data->log_data.origin_addr, &rl->request_line_data.request_target.host, data->origin_addr_len);
        data->log_data.origin_addr_type = ipv4_addr_t;
        ret = connect_to_origin(AF_INET, key);
        break;

    case domain_addr_t:

        printf("es domain_addr_t\n");

        if (resolve(rl->request_line_data.request_target.host.domain, key->s, data->client_fd, &rl->resolve_info) != RESOLVE_ERROR)
        {
            ret = REQUEST_RESOLVE;

            memcpy(data->log_data.origin_addr.domain, rl->request_line_data.request_target.host.domain ,strlen((char*)rl->request_line_data.request_target.host.domain)+1);
            data->log_data.origin_addr_type = domain_addr_t;

            if (SELECTOR_SUCCESS != selector_set_interest(key->s, key->fd, OP_NOOP)){
                data->status = INTERNAL_SERVER_ERROR;
                ret = ERROR;
            }
        }
        else
        {
            data->status = INTERNAL_SERVER_ERROR;
            ret = ERROR;
            goto finally;
        }

        break;
    }
   //   printf("1 origin form: %s: %d\n",(char*) data->client.request_line.request_line_data.request_target.origin_form, strlen((char *)rl->request_line_data.request_target.origin_form));
 // printf("2 origin form: %s: %d\n",(char*) rl->request_line_data.request_target.origin_form, strlen((char *)rl->request_line_data.request_target.origin_form));
    strcpy(data->log_data.origin_form,(char*) rl->request_line_data.request_target.origin_form);
    strcpy(data->log_data.method, (char*)rl->request_line_data.method);
    data->log_data.origin_port = rl->request_line_data.request_target.port;
    get_current_date_string(data->log_data.date);
    finally:
        return ret;
}
////////////////////////////////////////////////////////////////////////////////
// REQUEST RESOLVE
////////////////////////////////////////////////////////////////////////////////
static unsigned request_resolve_done(struct selector_key * key){
    printf("request resolve done\n");
    struct httpd *data = ATTACHMENT(key);

    struct request_line_st * rl = &data->client.request_line;

    if(rl->resolve_info.status != RESOLVE_OK){
        data->status = BAD_GATEWAY;
        return ERROR;
    }
    if(rl->resolve_info.qty == 0){
        printf("tengo 0 ips \n");
        if(rl->resolve_info.type == IPV4){
            printf("CAMBIO A IPV6");
            rl->resolve_info.type = IPV6;
            return request_line_process(rl,key);
        }else{
            data->status = BAD_GATEWAY;
            return ERROR;
        }
    }else{
        struct sockaddr_storage storage  = rl->resolve_info.storage[rl->resolve_info.qty -1];
        if(rl->resolve_info.type == IPV4){
            printf("resolve done es ipv4\n");
            struct sockaddr_in  * sin = (struct sockaddr_in * ) &storage;
            sin->sin_port = rl->request_line_data.request_target.port;

        }else{
            printf("resolve done es ipv6\n");
            struct sockaddr_in6 * sin6 = (struct sockaddr_in6 *) &storage;
            sin6->sin6_port = rl->request_line_data.request_target.port;

        }
        rl->resolve_info.qty--;
        data->origin_addr_len = sizeof(storage);
        memcpy(&data->origin_addr,&storage,data->origin_addr_len);
        rl->resolve_info.qty--;
        char buff[50];
        sockaddr_to_human(buff, 50, (const struct sockaddr *)&storage);
        printf("storage done = %s\n", buff);
        return connect_to_origin(storage.ss_family,key);
    }

    return ERROR;
}

////////////////////////////////////////////////////////////////////////////////
// CONNECTING
////////////////////////////////////////////////////////////////////////////////

static unsigned connect_to_origin(int origin_family,struct selector_key*key){
    struct httpd *data = ATTACHMENT(key);
  //  char buff2[30];

  //  sockaddr_to_human(buff2, 50, (const struct sockaddr*)&data->origin_addr);
    //printf("%s\n", buff2);

    bool retry_connect = false;
    int origin_fd = data->origin_fd;

    if(origin_fd != -1){
        retry_connect = true;
        close(origin_fd);
        selector_unregister_fd(key->s,origin_fd);
    }

    data->status = OK;
    unsigned ret = CONNECTING;
    origin_fd = socket(origin_family, SOCK_STREAM, IPPROTO_TCP);
    if (origin_fd < 0)
    {
        data->status = INTERNAL_SERVER_ERROR;
        goto finally;
    }
    printf("Origin fd: %d\n",origin_fd);
    data->origin_fd = origin_fd;
    
    if(selector_fd_set_nio(origin_fd) == -1){
        data->status = INTERNAL_SERVER_ERROR;
        goto finally;
    }
    if(connect(origin_fd,(const struct sockaddr*)&data->origin_addr,data->origin_addr_len) == -1){
        if(errno == EINPROGRESS){
            // se esta conectando
            printf("Connect to origin EINPROGRESS origin_fd %d\n",origin_fd);
            // registro el origin_fd para escritura para que me avise cuando si conectó o falló conexión
    

            selector_status ss = selector_register(key->s, origin_fd, &httpd_handler, OP_WRITE, data);
            printf("termino de registrar\n");
            if(ss != SELECTOR_SUCCESS){
                printf("fail register origin_fd to OP_WRITE\n");
                data->status = INTERNAL_SERVER_ERROR;
                goto finally;
            }
        }else{
            // falló conexión
            printf("Connect to origin error\n");
            // TODO: mandar mensaje al usuario supongo (al devolver ERROR, CREO que todos los recursos se liberan en httpd_done)
            data->status = errno_response(errno);
            goto finally;
         }
    }else{
        printf("Connect to origin devuelve otra cosa: %d\n");
    }
finally:
    printf("termina connect to origin: %d\n",ret);
    return data->status != OK ? ERROR : ret;
}

static void connecting_init(const unsigned state,struct selector_key *key){
    assert(state == CONNECTING);
    printf("connecting init\n");
    struct connecting_st * connecting = &(ATTACHMENT(key)->origin.connecting);

    connecting->client_fd = ATTACHMENT(key)->client_fd;
    connecting->origin_fd = ATTACHMENT(key)->origin_fd;
}



static enum httpd_state get_next_state(char * method){
    if(stricmp(method,"CONNECT") == 0){
        
        return COPY;
    }else{
        printf("request line write go\n");
        return REQUEST_LINE_WRITE;
    }
}

static unsigned connecting_done(struct selector_key *key){

    unsigned ret = ERROR;
    printf("Connecting done\n");
    int socket_error;
    struct httpd *data = ATTACHMENT(key);
    socklen_t socket_error_len = sizeof(socket_error);
    data->status = OK;
    struct connecting_st * connecting = &(ATTACHMENT(key)->origin.connecting);
  
    // verifico si se conectó exitosamente al origin server
    if(getsockopt(connecting->origin_fd,SOL_SOCKET,SO_ERROR,&socket_error,&socket_error_len) == 0){
        if(socket_error == 0){
            // se conectó bien
            printf("Me conecte bien a fd %d\n", connecting->origin_fd);
            if(stricmp(data->log_data.method,"CONNECT") == 0){
                strcpy(data->log_data.status_code,"200");
            }
        
            // quiero leer del cliente
            if (SELECTOR_SUCCESS != selector_set_interest(key->s, connecting->client_fd, OP_NOOP))
            {
                data->status = INTERNAL_SERVER_ERROR;
                goto finally;
            }
       
            if (SELECTOR_SUCCESS != selector_set_interest(key->s, connecting->origin_fd, OP_NOOP)){
                data->status = INTERNAL_SERVER_ERROR;
                goto finally;
            }

            ret = get_next_state((char * )ATTACHMENT(key)->client.request_line.request_line_data.method);
            goto finally;
        }else{


            if (SELECTOR_SUCCESS != selector_set_interest(key->s, data->client_fd, OP_NOOP)){


                data->status = INTERNAL_SERVER_ERROR;
                goto finally;

            }


            printf("2.socket_error == %d\n",socket_error);
            // hubo error en la conexión
            // TODO a futuro supongo que habrá un estado para reintentar conexión o devolver mensaje al usuario
            data->status = errno_response(errno);

            strcpy(data->log_data.status_code, error_responses[data->status].status);
            register_access(&data->log_data);
            ret = REQUEST_RESOLVE;
            goto finally;

        }
    }else{
        
        printf("getsockopt != 0\n");
        data->status = INTERNAL_SERVER_ERROR;
        goto finally;
    }

   
finally:
    return ret;
}

////////////////////////////////////////////////////////////////////////////////
// REQUEST LINE WRITE
////////////////////////////////////////////////////////////////////////////////

static void request_line_write_init(const unsigned state,struct selector_key *key){ 
    struct httpd *data = ATTACHMENT(key);
    assert(state == REQUEST_LINE_WRITE && data->origin_fd != -1);
    struct request_line_st* rl = &(data->client.request_line);

    size_t method_len = strlen((char*)rl->request_line_data.method);
 
    size_t origin_form_len = strlen((char*)rl->request_line_data.request_target.origin_form);

    rl->data.data_to_send_len = method_len + origin_form_len + 12;
    rl->data.data_to_send = (uint8_t*)malloc( rl->data.data_to_send_len);
 


    if(-1 == sprintf((char*)rl->data.data_to_send,"%s %s HTTP/%d.%d\r\n",(char*)rl->request_line_data.method,(char*)rl->request_line_data.request_target.origin_form,1,0)){
        abort();
    }
    rl->data.data_to_send[rl->data.data_to_send_len] = '\0';
    buffer *b = &rl->data.data_to_send_buffer;
    buffer_init(b, rl->data.data_to_send_len,rl->data.data_to_send);
    buffer_write_adv(b,rl->data.data_to_send_len);
    //read_request_line(rl, key->s, data->origin_fd);
    if (SELECTOR_SUCCESS != selector_set_interest(key->s,data->origin_fd, OP_WRITE))
    {
        abort();
    }
}

static void request_line_write_on_departure(const unsigned state,struct selector_key *key){
    struct httpd *data = ATTACHMENT(key);
    struct request_line_st* rl = &(data->client.request_line);
    free(rl->data.data_to_send);

}

static bool send_buffer(int read_fd,int write_fd, buffer *b,fd_selector s, struct data_to_send* data,bool *error){
    size_t rbytes;
    /* quiero leer en el write buffer de copy */
    uint8_t *write_buffer_ptr = buffer_read_ptr(b, &rbytes);

    ssize_t numBytesWritten = send(write_fd, write_buffer_ptr, rbytes,MSG_NOSIGNAL);
  
    bool done = false;

    if(numBytesWritten < 0){
        *error = true;
         abort();
    }
    else if (numBytesWritten == 0)
    {
    
        abort();
    }
    else
    {
        // se escribió algo
        size_t written = numBytesWritten < rbytes ? numBytesWritten : rbytes;

        buffer_read_adv(b, written);
        print_buffer(b);
        data->data_to_send_written += written;
        bool can_read = buffer_can_read(b);
        bool finished_writting = data->data_to_send_written >= data->data_to_send_len;
        if(finished_writting){
  
            if (read_fd > -1 && SELECTOR_SUCCESS != selector_set_interest(s,read_fd, OP_NOOP))
            {
                *error = true;
                goto finally;
            }

            if (write_fd > -1 && SELECTOR_SUCCESS != selector_set_interest(s,write_fd, OP_NOOP))
            {
                *error = true;
                goto finally;
            }
            done = true;
        }
        else if (!finished_writting && can_read)
        {
          
            // no termine de enviar al origin server toda la request line y puedo seguir leyendo del buffer
        }
        else if (!can_read)
        {
           
            *error = true;
        }
            //read first line
    }
finally:
    return done;
}

static unsigned request_line_write(struct selector_key *key){

    struct httpd *data = ATTACHMENT(key);
    assert(data->origin_fd == key->fd);

    struct request_line_st* rl = &(data->client.request_line);
    buffer *b = &rl->data.data_to_send_buffer;
    unsigned ret = REQUEST_LINE_WRITE;
    bool error = false;
    bool done = send_buffer(data->client_fd, data->origin_fd, b, key->s, &rl->data, &error);
    if(!error){
        if(done){
            ret = REQUEST_MESSAGE;
        }
    }

finally :
    return error ? ERROR : ret;
}

////////////////////////////////////////////////////////////////////////////////
// REQUEST MESSAGE
////////////////////////////////////////////////////////////////////////////////



static void content_length_on_value_end(struct request_message_parser* parser,struct  log_data*log_data){
    assert(parser != NULL && parser->current_detection != NULL);
    set_content_length(parser,atoi(get_detection_value(parser)));
    printf("CONTENT LENGTH = %d\n", parser->content_lenght);
}



static void request_message_init(const unsigned state,struct selector_key *key){
    printf("request message init\n");
    struct httpd *data = ATTACHMENT(key);
    struct request_message_st *rm = &data->client.request_message;
    rm->rb = &data->from_origin_buffer;
    request_message_parser_init(&rm->parser,4,true); // <= cantidad de headers a tener en cuenta, podria mejorarse la interfaz para que no sea necesario pasarselo
    int len = data->origin_addr.ss_family == AF_INET ? INET_ADDRSTRLEN + 6 : INET6_ADDRSTRLEN +6;
    char *host_buffer = (char *)malloc(len);
    
    // El parser de header es case insensitive
    add_header(&rm->parser, "Host", HEADER_REPLACE,get_origin_string(data->log_data.origin_addr,data->log_data.origin_addr_type,data->log_data.origin_port), NULL);
    add_header(&rm->parser, "Content-Length", (HEADER_STORAGE | HEADER_SEND),NULL, content_length_on_value_end);
    add_header(&rm->parser, "Connection", HEADER_IGNORE,NULL, NULL);
    add_header(&rm->parser, "Proxy-Authorization",  (HEADER_STORAGE | HEADER_SEND),NULL, decode_credentials);
    if (SELECTOR_SUCCESS != selector_set_interest(key->s,data->client_fd, OP_READ))
    {
            abort();
    }
    if(buffer_can_read(rm->rb)){

        // ademas de la request line, se escribieron headers y/o body en el buffer de lectura del cliente
        if (SELECTOR_SUCCESS != selector_set_interest(key->s,data->origin_fd, OP_WRITE))
        {
            abort();
        }
    }
}

static bool read_message(int read_fd,int write_fd,buffer* rb,fd_selector s,bool * error){
    bool done = false;
    size_t wbytes;
    uint8_t *read_buffer_ptr = buffer_write_ptr(rb, &wbytes);
    printf("wbytes = %ld\n", wbytes);
    ssize_t numBytesRead = recv(read_fd, read_buffer_ptr, wbytes,0);
    printf("numBytesRead = %ld\n", numBytesRead);
    if (numBytesRead > 0)
    {
        buffer_write_adv(rb, numBytesRead);
        if(!buffer_can_write(rb)){
            if (SELECTOR_SUCCESS != selector_set_interest(s,read_fd, OP_NOOP))
            {
                *error = true;
                goto finally;
            }
        }
        if (SELECTOR_SUCCESS != selector_set_interest(s,write_fd, OP_WRITE))
        {
            *error = true;
            goto finally;
        }
    }else if(numBytesRead <0){
        *error = true;
        goto finally;
    }else{
        if (SELECTOR_SUCCESS != selector_set_interest(s,read_fd, OP_NOOP))
        {
                *error = true;
                goto finally;
        }
        done = true;
    }
 
finally:
    return done;
}

static unsigned request_message_read(struct selector_key* key){
       //printf("request message READ\n");
    struct httpd *data = ATTACHMENT(key);
    struct request_message_st *rm = &data->client.request_message;
    buffer * client_rb = rm->rb;
    bool error = false;
    unsigned ret = REQUEST_MESSAGE;
    bool done = read_message(data->client_fd, data->origin_fd, client_rb, key->s,&error);
    if (error)
    {
        data->status = INTERNAL_SERVER_ERROR;
        ret = ERROR;
    }else if(done){
        ret = DONE;
    }
    
    return ret;
}

static bool send_message(int read_fd, int write_fd, buffer *rb, request_message_parser *parser, fd_selector s, bool *error,struct log_data*log_data)
{

    bool done = false;
    done = request_message_parser_consume(parser,rb,error,log_data);
    if(done){
        if(*error){
            goto finally;
        }
    }
        
  
    if(parser->data_index > 0){
        ssize_t numBytesWritten = send(write_fd, parser->data, parser->data_index,MSG_NOSIGNAL);
        if(numBytesWritten <= 0){
    
            *error = true;
            goto finally;
        }
        if(numBytesWritten < parser->data_index){
            // si se envió menos de lo que parseé, debo escribir lo que parseé demás devuelta en el buffer
           
            for (unsigned i = numBytesWritten-1; i <  parser->data_index-1; i++){
                buffer_write(rb, parser->data[i]);
            }
            buffer_write_adv(rb, parser->data_index - numBytesWritten);
        }
    }
    parser->data_index = 0;
    if(!done){
        if(buffer_can_write(rb)){   
            if (SELECTOR_SUCCESS != selector_set_interest(s,read_fd, OP_READ))
            {
                *error = true;
                goto finally;
            }
        }
        if(!buffer_can_read(rb)){   
            if (SELECTOR_SUCCESS != selector_set_interest(s,write_fd, OP_NOOP))
            {
                *error = true;
                goto finally;
            }
        }
    }else if (SELECTOR_SUCCESS != selector_set_interest(s,read_fd, OP_NOOP) || SELECTOR_SUCCESS != selector_set_interest(s,write_fd, OP_NOOP)){
            *error = true;
            goto finally;
    }
        
           
finally:
    return done;
}

static unsigned request_message_write(struct selector_key* key){
      // printf("request message WRITE\n");
    struct httpd *data = ATTACHMENT(key);
    struct request_message_st *rm = &data->client.request_message;

    buffer *client_rb = rm->rb;
    bool error = false;
    unsigned ret = REQUEST_MESSAGE;
   
    bool done = send_message(data->client_fd, data->origin_fd, client_rb, &rm->parser, key->s, &error,&data->log_data);
    if(error){
        data->status = INTERNAL_SERVER_ERROR;
        ret = ERROR;
    }else if(done){
        ret = RESPONSE_LINE_READ;
    }
    return ret;
}

////////////////////////////////////////////////////////////////////////////////
// RESPONSE LINE
////////////////////////////////////////////////////////////////////////////////

static void response_line_read_init(const unsigned state,struct selector_key *key){
    printf("response_line_init\n");
    assert(state == RESPONSE_LINE_READ);
    struct httpd *data = ATTACHMENT(key);
    struct response_line_st* rl = &(data->client.response_line);
    response_line_parser_init(&(rl->parser));
    rl->parser.response_line = &(data->client.response_line.response_line_data);
    rl->parser.response_line->code_counter = 0;
    rl->parser.response_line->message_counter = 0;
    rl->rb = &(data->from_origin_buffer);

    if (SELECTOR_SUCCESS != selector_set_interest(key->s,data->origin_fd, OP_READ))
    {
        abort();
    }
}

static unsigned response_line_read(struct selector_key *key)
{
    printf("response_line_read\n");
    struct response_line_st* rl = &(ATTACHMENT(key)->client.response_line);
    struct httpd *data = ATTACHMENT(key);

    buffer *b = rl->rb;
    data->status = OK;
    size_t wbytes;
    uint8_t *read_buffer_ptr = buffer_write_ptr(b, &wbytes);
    printf("wbytes = %ld\n", wbytes);
    ssize_t numBytesRead = recv(key->fd, read_buffer_ptr, wbytes,0);
    printf("numBytesRead = %ld\n", numBytesRead);
    unsigned ret = RESPONSE_LINE_READ;
    if (numBytesRead > 0)
    {
        buffer_write_adv(b, numBytesRead);
        bool done = response_line_parser_consume(b, &rl->parser, &data->status);
        if(done){
            if(data->status != OK){
                ret = ERROR;
            }else{
                printf("termine de parsear sin error\n");
                printf("codigo: %s\n", rl->response_line_data.status_code);
                printf("message: %s\n", rl->response_line_data.status_message);
                printf("version %d.%d\n", rl->response_line_data.version_major, rl->response_line_data.version_minor);
            
                strcpy(data->log_data.status_code, (char*)rl->response_line_data.status_code);
                ret = RESPONSE_LINE_WRITE;
                if (SELECTOR_SUCCESS != selector_set_interest(key->s,data->origin_fd, OP_NOOP))
                {
                    abort();
                }
            }
        }
    }
    else
    {
        ret = ERROR;
    }

    return data->status != OK ? ERROR : ret;
}
static void request_message_on_departure(const unsigned state, struct selector_key *key){
    struct httpd *data = ATTACHMENT(key);
    struct request_message_st *rm = &data->client.request_message;
    request_message_parser_destroy(&rm->parser);
}


////////////////////////////////////////////////////////////////////////////////
// RESPONSE LINE WRITE
////////////////////////////////////////////////////////////////////////////////

static void response_line_write_init(const unsigned state,struct selector_key *key){
    printf("response_line_write_init\n");


    struct httpd *data = ATTACHMENT(key);
    assert(state == RESPONSE_LINE_WRITE && data->origin_fd != -1);
    struct response_line_st* rl = &(data->client.response_line);

    size_t code_len = strlen((char*)rl->response_line_data.status_code);
    printf("code len %ld\n", code_len);
    size_t status_msg_len = strlen((char*)rl->response_line_data.status_message);
    printf("status msg len %ld\n", status_msg_len);
    rl->data.data_to_send_len = code_len + status_msg_len + 12;
    rl->data.data_to_send = (uint8_t*)malloc( rl->data.data_to_send_len);

    if(-1 == sprintf((char*)rl->data.data_to_send,"HTTP/%d.%d %s %s\r\n",1,0, (char*)rl->response_line_data.status_code, (char*)rl->response_line_data.status_message)){
        abort();
    }
    rl->data.data_to_send[rl->data.data_to_send_len] = '\0';
    printf("request_line_to_send: %s\ntotal_len %d\n", rl->data.data_to_send,rl->data.data_to_send_len);
    buffer *b = &rl->data.data_to_send_buffer;
    buffer_init(b, rl->data.data_to_send_len,rl->data.data_to_send);
    buffer_write_adv(b,rl->data.data_to_send_len);
    //read_request_line(rl, key->s, data->origin_fd);
    if (SELECTOR_SUCCESS != selector_set_interest(key->s,data->client_fd, OP_WRITE))
    {
        abort();
    }
}

static void response_line_write_on_departure(const unsigned state,struct selector_key *key){
    struct httpd *data = ATTACHMENT(key);
    struct response_line_st* rl = &(data->client.response_line);
    free(rl->data.data_to_send);
}

static unsigned response_line_write(struct selector_key *key){
    printf("RESPONSE_LINE_WRITE\n");
    struct httpd *data = ATTACHMENT(key);
    data->status = OK;
    assert(data->client_fd == key->fd);

    struct response_line_st* rl = &(data->client.response_line);
    buffer *b = &rl->data.data_to_send_buffer;
    unsigned ret = RESPONSE_LINE_WRITE;
    bool error = false;
    bool done = send_buffer(data->origin_fd, data->client_fd, b, key->s, &rl->data, &error);
    if(!error){
        if(done){
            ret = RESPONSE_MESSAGE;
        }
    }

finally :
    return error ? ERROR : ret;
}
////////////////////////////////////////////////////////////////////////////////
// RESPONSE MESSAGE
////////////////////////////////////////////////////////////////////////////////

static void response_message_init(const unsigned state,struct selector_key *key){
    printf("response message init\n");
    struct httpd *data = ATTACHMENT(key);
    struct request_message_st *rm = &data->origin.request_message;
    rm->rb = &data->from_origin_buffer;
    request_message_parser_init(&rm->parser,1,true);
    add_header(&rm->parser, "Content-Length", (HEADER_STORAGE | HEADER_SEND),NULL, content_length_on_value_end);
    
    if (SELECTOR_SUCCESS != selector_set_interest(key->s,data->origin_fd, OP_READ))
    {
        abort();
    }
    if(buffer_can_read(rm->rb)){
        printf("buffer can read\n");
        // ademas de la request line, se escribieron headers y/o body en el buffer de lectura del cliente
        if (SELECTOR_SUCCESS != selector_set_interest(key->s,data->client_fd, OP_WRITE))
        {
            abort();
        }
    }
}


static unsigned response_message_write(struct selector_key* key){
      // printf("request message WRITE\n");
    struct httpd *data = ATTACHMENT(key);
    struct request_message_st *rm = &data->origin.request_message;

    buffer *origin_rb = rm->rb;
    bool error = false;
    unsigned ret = RESPONSE_MESSAGE;
   
    bool done = send_message(data->origin_fd, data->client_fd, origin_rb, &rm->parser, key->s, &error,&data->log_data);
    if(error){
        data->status = INTERNAL_SERVER_ERROR;
        ret = ERROR;
    }else if(done){
        printf(" rm METHOD: %s\n", data->log_data.method);
        ret = DONE;
    }
    return ret;
}

static unsigned response_message_read(struct selector_key* key){
    struct httpd *data = ATTACHMENT(key);
    struct request_message_st *rm = &data->origin.request_message;
    buffer * origin_rb = rm->rb;
    bool error = false;
    unsigned ret = REQUEST_MESSAGE;
    bool done = read_message(data->origin_fd, data->client_fd, origin_rb, key->s,&error);
    if (error)
    {
        data->status = INTERNAL_SERVER_ERROR;
        ret = ERROR;
    }else if(done){
        ret = DONE;
    }
    
    return ret;
}


static void response_message_on_departure(const unsigned state, struct selector_key *key){
    struct httpd *data = ATTACHMENT(key);
    struct request_message_st *rm = &data->origin.request_message;
    printf(" 1rm d METHOD: %s\n", data->log_data.method);
    request_message_parser_destroy(&rm->parser);
    printf(" 2rm d METHOD: %s\n", data->log_data.method);
}


////////////////////////////////////////////////////////////////////////////////
// ERROR
////////////////////////////////////////////////////////////////////////////////

static void error_init(const unsigned state,struct selector_key * key){
    assert(state == ERROR);
    printf("ERROR_INIT\n");
    struct httpd *data = ATTACHMENT(key);

    struct response_line_st * rl = &data->client.response_line;


    error_status_code status = data->status;
    const struct error_response response = error_responses[status];
    memcpy(data->log_data.status_code,response.status,strlen(response.status));
    rl->data.data_to_send_len = strlen(response.status_message) + 15;
    rl->data.data_to_send = (uint8_t *)malloc(rl->data.data_to_send_len);
    rl->data.data_to_send_written = 0;
    if(rl->data.data_to_send == NULL){
        abort();
    }
    if (-1 == sprintf((char*)rl->data.data_to_send, "HTTP/%d.%d %s %s\r\n", response.http_version_major, response.http_version_minor, response.status, response.status_message))
    {
        abort();
    }

    buffer_init(&rl->data.data_to_send_buffer, rl->data.data_to_send_len, rl->data.data_to_send);
    buffer_write_adv(&rl->data.data_to_send_buffer, rl->data.data_to_send_len);

    if (SELECTOR_SUCCESS != selector_set_interest(key->s,data->client_fd, OP_WRITE))
    {
        abort();
    }
}

static unsigned error_write(struct selector_key* key){
    printf("ERROR_WRITE\n");
    struct httpd *data = ATTACHMENT(key);
    assert(data->client_fd == key->fd);

    struct response_line_st* rl = &(data->client.response_line);

    buffer *b = &rl->data.data_to_send_buffer;
    unsigned ret = ERROR;
    bool error = false;
    bool done = send_buffer(data->origin_fd, data->client_fd, b, key->s, &rl->data, &error);
    if(!done){
        if(error){
            memcpy(data->log_data.status_code,"500",4);
            ret = DONE;
        }
    }else{
        ret = DONE;
    }

finally :
    return ret;
}

////////////////////////////////////////////////////////////////////////////////
// COPY
////////////////////////////////////////////////////////////////////////////////

static void copy_init(const unsigned state,struct selector_key *key){
    assert(state == COPY);
    printf("COPY_INIT\n");
    struct httpd *data = ATTACHMENT(key);
    struct copy_st *copy = &data->client.copy;

    copy->fd = data->client_fd;
    copy->copy_to = &data->origin.copy;
    copy->interest = OP_READ | OP_WRITE;
    copy->rb = &data->from_origin_buffer;
    copy->wb = &data->from_client_buffer;

    copy = &data->origin.copy;
    copy->fd = data->origin_fd;
    copy->copy_to = &data->client.copy;
    copy->interest = OP_READ | OP_WRITE;
    copy->rb = &data->from_client_buffer;
    copy->wb = &data->from_origin_buffer;
    if (SELECTOR_SUCCESS != selector_set_interest(key->s,data->client_fd, OP_READ))
    {
        abort();
    }

      if (SELECTOR_SUCCESS != selector_set_interest(key->s,data->origin_fd, OP_READ))
    {
       
        abort();
    }

}

static struct copy_st *get_copy_from_key(struct selector_key *key){
    struct copy_st *copy = &ATTACHMENT(key)->client.copy;
    return copy->fd == key->fd ? copy : copy->copy_to;
}

static void selector_set_new_interest(struct copy_st* copy,fd_selector s){
    assert(copy->fd > 0);

    fd_interest new_interests = OP_NOOP;

    if((copy->interest & OP_READ) && buffer_can_write(copy->rb)){
      
        new_interests |= OP_READ;
    }else{
         printf("no agrego read\n");
    }
    if((copy->interest & OP_WRITE) && buffer_can_read(copy->wb)){

    
        new_interests |= OP_WRITE;
    }else{
        printf("no agrego write\n");
    }
    
    if(SELECTOR_SUCCESS != selector_set_interest(s,copy->fd,new_interests)){
        abort();
    }
}
static unsigned copy_read(struct selector_key *key){
    printf("COPY_READ\n");
    struct copy_st *copy = get_copy_from_key(key);
    struct httpd *data = ATTACHMENT(key);

    size_t wbytes;
    /* quiero escribir en el read buffer de copy */
    uint8_t *read_buffer_ptr = buffer_write_ptr(copy->rb, &wbytes);
    ssize_t numBytesRead = recv(key->fd, read_buffer_ptr, wbytes,0);

    unsigned ret = COPY;

   
    if(numBytesRead < 0){
        data->status = INTERNAL_SERVER_ERROR;
        ret = ERROR;
    }else if(numBytesRead == 0){
        // si llega EOF entonces debo quitar OP_READ del copy actual y OP_WRITE del copy_to
        // la conexión no termina ya que puede quedar data en el buffer con dirección contraria
        copy->interest &= ~OP_READ;
        shutdown(copy->fd, SHUT_RD);
        copy->copy_to->interest &= ~OP_WRITE;
        shutdown(copy->copy_to->fd, SHUT_WR);

        if(copy->interest == OP_NOOP){
            // una de las partes no puede leer ni enviar más datos

            return DONE;
        }

    }else{
        // se leyó algo
        buffer_write_adv(copy->rb, numBytesRead);
        if(get_disectors_enabled() && copy->fd == ATTACHMENT(key)->client_fd){
            // Sniffeo lo que envia el cliente
                printf("SNIFFEO ESCRITURA CLIENTE\n");
            // Quiero ver si es una HTTP Request
            http_disector_consume(&ATTACHMENT(key)->http_disector,copy->rb);
            // Quiero ver si es un mensaje POP3 
            pop3_disector_consume(&ATTACHMENT(key)->pop3_disector,copy->rb);
        }
        //print_buffer(copy->rb);
        //print_buffer(copy->wb);
    }
    selector_set_new_interest(copy,key->s);
    selector_set_new_interest(copy->copy_to,key->s);
    return ret;
}

static unsigned copy_write(struct selector_key *key){

    printf("COPY_WRITE\n");
    struct copy_st *copy = get_copy_from_key(key);
    struct httpd *data = ATTACHMENT(key);

    size_t rbytes;
    /* quiero leer en el write buffer de copy */
    uint8_t *write_buffer_ptr = buffer_read_ptr(copy->wb, &rbytes);
    ssize_t numBytesWritten = send(key->fd, write_buffer_ptr, rbytes,MSG_NOSIGNAL);
    unsigned ret = COPY;

 
    if(numBytesWritten < 0){
        data->status = INTERNAL_SERVER_ERROR;
        ret = ERROR;
    }else if(numBytesWritten == 0){
        printf("send devuelve 0\n");
        // si llega EOF entonces debo quitar OP_WRITE del copy actual y OP_READ del copy_to
        // la conexión no termina ya que puede quedar data en el buffer con dirección contraria
        copy->interest &= ~OP_WRITE;
        shutdown(copy->fd, SHUT_WR);
        if(copy->copy_to->fd != -1){
            copy->copy_to->interest &= ~OP_READ;
            shutdown(copy->copy_to->fd, SHUT_RD);
        }
      
        if(copy->interest == OP_NOOP){
            // una de las partes no puede leer ni enviar más datos
            printf("interest == NOOP\n");
            return DONE;
        }

    }else{
        // se escribió algo

        if(get_disectors_enabled() && copy->fd == ATTACHMENT(key)->client_fd){
            // Sniffeo lo que lee el cliente
            printf("SNIFFEO LECTURA CLIENTE\n");
            // Quiero ver si es un mensaje POP3 
            pop3_disector_consume(&ATTACHMENT(key)->pop3_disector,copy->wb);
        }
        buffer_read_adv(copy->wb, numBytesWritten);

    }
    selector_set_new_interest(copy,key->s);
    selector_set_new_interest(copy->copy_to,key->s);
    return ret;
}

static error_status_code errno_response(int e){

    // Si no sabemos manejar el error, entonces el error es de nuestra parte
    error_status_code ret = INTERNAL_SERVER_ERROR;
    switch (e){
        case ECONNREFUSED:
        case EHOSTUNREACH:
        case EBADF:
        case EFAULT:
        case ENETUNREACH:
                ret = NOT_FOUND;
            break;
        case ETIMEDOUT: 
            ret = GATEWAY_TIMEOUT;
            break;
    }
    return ret;
}
