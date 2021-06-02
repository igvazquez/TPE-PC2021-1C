#include "../include/httpdnio.h"
#include "../include/request_line.h"
#include "../include/stm.h"
#include "../include/buffer.h"
#include "../include/netutils.h"
#include <sys/socket.h>
#include<stdio.h>
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
#define MAX_BUFF_SIZE 1

#define N(x) (sizeof(x)/sizeof((x)[0]))

/** obtiene el struct (httpd *) desde la llave de selección  */
#define ATTACHMENT(key) ( (struct httpd *)(key)->data)



static void httpd_read   (struct selector_key *key);
static void httpd_write  (struct selector_key *key);
static void httpd_block  (struct selector_key *key);
static void httpd_close  (struct selector_key *key);


static void connecting_init(const unsigned state,struct selector_key *key);
static unsigned connecting_done(struct selector_key *key);

static void request_line_read_init(const unsigned state,struct selector_key *key);
static unsigned request_line_read(struct selector_key *key);

static void request_line_write_init(const unsigned state,struct selector_key *key);
static unsigned request_line_write(struct selector_key *key);
static void request_line_write_on_departure(const unsigned state, struct selector_key *key);

static void copy_init(const unsigned state,struct selector_key *key);
static unsigned copy_read(struct selector_key *key);
static unsigned copy_write(struct selector_key *key);



/** maquina de estados general */
enum httpd_state {
    REQUEST_LINE_READ,
    CONNECTING,
    REQUEST_LINE_WRITE,
 
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

struct request_line_st{
    buffer *rb;
    
    struct request_line request_line_data;
    struct request_line_parser parser;
    uint8_t *rl_to_send;
    unsigned rl_to_send_len;
    unsigned rl_to_send_written;
    buffer rl_to_send_buffer;
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
        struct copy_st copy;
    } client;

    
    /* información del server origen */
    struct sockaddr_storage origin_addr;
    socklen_t origin_addr_len;
    int origin_fd;

    /* estados para el origin_fd */
    union {
        struct connecting_st connecting;
        struct copy_st copy;
    } origin;

};


/** Definición de handlers para cada estado */
static const struct state_definition client_statbl[] = {

    {.state = REQUEST_LINE_READ,
     .on_arrival = request_line_read_init,
     .on_read_ready = request_line_read},
    {.state = CONNECTING,
     .on_arrival = connecting_init,
     .on_write_ready = connecting_done},
    {.state = REQUEST_LINE_WRITE,
     .on_arrival = request_line_write_init,
     .on_write_ready = request_line_write,
     .on_departure = request_line_write_on_departure
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

    if(ERROR == st || DONE == st) {
        httpd_done(key);
    }
}

static void
httpd_write(struct selector_key *key) {
    struct state_machine *stm   = &(ATTACHMENT(key)->stm);

    const enum httpd_state st = stm_handler_write(stm, key);

    if(ERROR == st || DONE == st) {

        httpd_done(key);
    }
}

static void
httpd_block(struct selector_key *key) {
    struct state_machine *stm   = &(ATTACHMENT(key)->stm);
    const enum httpd_state st = stm_handler_block(stm, key);

    if(ERROR == st || DONE == st) {
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
    return ret;
}

static unsigned connect_to_origin(int origin_family,const struct sockaddr* addr, struct selector_key*key);

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
    state->client_addr_len = client_addr_len;

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
    //TODO liberar bien los recursos
    //socks5_destroy(state);
}

////////////////////////////////////////////////////////////////////////////////
// REQUEST LINE READ
////////////////////////////////////////////////////////////////////////////////

static void request_line_read_init(const unsigned state,struct selector_key *key){
    printf("request_line_init\n");
    assert(state == REQUEST_LINE_READ);
    struct httpd *data = ATTACHMENT(key);
    struct request_line_st* rl = &(data->client.request_line);
    request_line_parser_init(&(rl->parser));
    rl->parser.request_line = &(data->client.request_line.request_line_data);
    rl->rb = &(data->from_origin_buffer);
}

static unsigned request_line_process(struct request_line *rl, struct selector_key *key);
static unsigned request_line_read(struct selector_key *key)
{
     printf("request_line_read\n");
    struct request_line_st* rl = &(ATTACHMENT(key)->client.request_line);

    buffer *b = rl->rb;
    bool error = false;
    size_t wbytes;
    uint8_t *read_buffer_ptr = buffer_write_ptr(b, &wbytes);
    printf("wbytes = %ld\n", wbytes);
    ssize_t numBytesRead = recv(key->fd, read_buffer_ptr, wbytes,0);
    printf("numBytesRead = %ld\n", numBytesRead);
    unsigned ret = REQUEST_LINE_READ;
    if (numBytesRead > 0)
    {
        buffer_write_adv(b, numBytesRead);
        bool done = request_line_parser_consume(b, &rl->parser, &error);
        if(done){
            if(error){
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

                //proceso la request line
                ret = request_line_process(&rl->request_line_data,key);
            }
            //termine de consumir request line;
            
        }
    }
    else
    {
        ret = ERROR;
    }

    return error ? ERROR : ret;
}

static unsigned request_line_process(struct request_line * rl,struct selector_key * key){
    unsigned ret = ERROR;
    struct sockaddr_in6 *addrV6;
    struct sockaddr_in *addrV4;


    switch (rl->request_target.host_type)
    {
    case ipv6_addr_t:
        addrV6 = &rl->request_target.host.ipv6;
        addrV6->sin6_port = rl->request_target.port;
        addrV6->sin6_family = AF_INET6;
        ret = connect_to_origin(AF_INET6, (const struct sockaddr *)addrV6, key);
        break;
    case ipv4_addr_t:
        addrV4 = &rl->request_target.host.ipv4;
        addrV4->sin_port = rl->request_target.port;
        addrV4->sin_family = AF_INET;
        ret = connect_to_origin(AF_INET, (const struct sockaddr *)addrV4, key);
        break;

    case domain_addr_t:
        ret = ERROR;
        break;
    }
    return ret;
}



////////////////////////////////////////////////////////////////////////////////
// CONNECTING
////////////////////////////////////////////////////////////////////////////////

static unsigned connect_to_origin(int origin_family,const struct sockaddr* addr, struct selector_key*key){
     
    char buff2[30];

    sockaddr_to_human(buff2, 50, addr);
    printf("%s\n", buff2);
    struct httpd *data = ATTACHMENT(key);
  

    bool error = false;
    unsigned ret = CONNECTING;
    int origin_fd = socket(origin_family, SOCK_STREAM, IPPROTO_TCP);
    if (origin_fd < 0)
    {
        error = true;
        goto finally;
    }
    printf("Origin fd: %d\n",origin_fd);
    data->origin_fd = origin_fd;
    
    if(selector_fd_set_nio(origin_fd) == -1){
        error = true;
        goto finally;
    }
    if(connect(origin_fd,addr,sizeof(*addr)) == -1){
        if(errno == EINPROGRESS){
            // se esta conectando
            printf("Connect to origin EINPROGRESS origin_fd %d\n",origin_fd);
            // registro el origin_fd para escritura para que me avise cuando si conectó o falló conexión
            selector_status ss = selector_register(key->s, origin_fd, &httpd_handler, OP_WRITE, data);

            if(ss != SELECTOR_SUCCESS){
                printf("fail register origin_fd to OP_WRITE\n");
                error = true;
                goto finally;
            }
        }else{
            // falló conexión
            printf("Connect to origin error\n");
            // TODO: mandar mensaje al usuario supongo (al devolver ERROR, CREO que todos los recursos se liberan en httpd_done)
            error = true;
            goto finally;
         }
    }else{
        printf("Connect to origin devuelve otra cosa: %d\n");
    }
finally:
    return error ? ERROR : ret;
}

static void connecting_init(const unsigned state,struct selector_key *key){
    assert(state == CONNECTING);
    printf("connecting init\n");
    struct connecting_st * connecting = &(ATTACHMENT(key)->origin.connecting);

    connecting->client_fd = ATTACHMENT(key)->client_fd;
    connecting->origin_fd = ATTACHMENT(key)->origin_fd;
}

static enum httpd_state get_next_state(char * method){
    if(strcmp(method,"CONNECT") == 0){
      
        return COPY;
    }else{
        return REQUEST_LINE_WRITE;
    }
}

static unsigned connecting_done(struct selector_key *key){
    printf("Connecting done\n");
    int socket_error;
    socklen_t socket_error_len = sizeof(socket_error);
    bool error = false;
    struct connecting_st * connecting = &(ATTACHMENT(key)->origin.connecting);
  
    // verifico si se conectó exitosamente al origin server
    if(getsockopt(connecting->origin_fd,SOL_SOCKET,SO_ERROR,&socket_error,&socket_error_len) == 0){
        if(socket_error == 0){
            // se conectó bien
            printf("Me conecte bien a fd %d\n", connecting->origin_fd);
        
            // quiero leer del cliente
            if (SELECTOR_SUCCESS != selector_set_interest(key->s, connecting->client_fd, OP_NOOP))
            {
                error = true;
                goto finally;
            }
       
            if (SELECTOR_SUCCESS != selector_set_interest(key->s, connecting->origin_fd, OP_NOOP))
            {
                error = true;
                goto finally;
            }
        }else{
            printf("2.socket_error == %d\n",socket_error);
            // hubo error en la conexión
            // TODO a futuro supongo que habrá un estado para reintentar conexión o devolver mensaje al usuario
            error = true;
            goto finally;
        }
    }else{
        
        printf("getsockopt != 0\n");
        error = true;
        goto finally;
    }

    char *method = (char * )ATTACHMENT(key)->client.request_line.request_line_data.method;
   
finally:
    return error ? ERROR : get_next_state(method);
}

////////////////////////////////////////////////////////////////////////////////
// REQUEST LINE WRITE
////////////////////////////////////////////////////////////////////////////////


static unsigned read_request_line(struct request_line_st* rl,fd_selector s,int origin_fd){
    printf("read_request_line\n");
    buffer *b = &rl->rl_to_send_buffer;
 
    printf("buffer to send\n");
    print_buffer(b);
    size_t wbytes;
    unsigned ret = REQUEST_LINE_WRITE;
    bool error = false;
    /* quiero escribir en el read buffer de client para que lo lea el origin */
    uint8_t *read_buffer_ptr = buffer_write_ptr(b, &wbytes);
    printf("wbytes = %ld\n", wbytes);
    if(wbytes == 0){
        printf("wbytes es 0 abort\n");
        error = true;
        goto finally;
    }

    int n = snprintf((char*)read_buffer_ptr, wbytes, (char*)rl->rl_to_send);
    
    printf("escribi %d bytes de la request line\n", n);
    if(n < 0){
         error = true;
        goto finally;
    }
  
    //rl->rl_to_send_read += n;
    printf("request_line_to_send = %s\n",(char*) rl->rl_to_send);
   /* if(rl->rl_to_send_read == rl->rl_to_send_len){
        printf("ya lei toda la request line\n");
    }*/
    if (SELECTOR_SUCCESS != selector_set_interest(s,origin_fd, OP_WRITE))
    {
        error = true;
        goto finally;
    }
finally:
    return error ? ERROR : ret;
}



static void request_line_write_init(const unsigned state,struct selector_key *key){
    printf("request_line_init\n");

    
    struct httpd *data = ATTACHMENT(key);
    assert(state == REQUEST_LINE_WRITE && data->origin_fd != -1);
    struct request_line_st* rl = &(data->client.request_line);

    size_t method_len = strlen((char*)rl->request_line_data.method);
    printf("len method %ld\n", method_len);
    size_t origin_form_len = strlen((char*)rl->request_line_data.request_target.origin_form);
    printf("origin_form_len method %ld\n", origin_form_len);
    rl->rl_to_send_len = method_len + origin_form_len + 13;
    rl->rl_to_send = (uint8_t*)malloc( rl->rl_to_send_len);
 
   
   

    if(-1 == sprintf((char*)rl->rl_to_send,"%s %s HTTP/%d.%d\r\n",(char*)rl->request_line_data.method,(char*)rl->request_line_data.request_target.origin_form,1,0)){
        abort();
    }
    rl->rl_to_send[rl->rl_to_send_len - 1] = '\0';
    printf("request_line_to_send: %s\ntotal_len %d\n", rl->rl_to_send,rl->rl_to_send_len);
    buffer *b = &rl->rl_to_send_buffer;
    buffer_init(b, rl->rl_to_send_len,rl->rl_to_send);
    buffer_write_adv(b,rl->rl_to_send_len);
    //read_request_line(rl, key->s, data->origin_fd);
    if (SELECTOR_SUCCESS != selector_set_interest(key->s,data->origin_fd, OP_WRITE))
    {
        abort();
    }
}

static void request_line_write_on_departure(const unsigned state,struct selector_key *key){
    struct httpd *data = ATTACHMENT(key);
    struct request_line_st* rl = &(data->client.request_line);
    free(rl->rl_to_send);
 
}


static unsigned request_line_write(struct selector_key *key){
    printf("REQUEST_LINE_WRITE\n");
    struct httpd *data = ATTACHMENT(key);
    assert(data->origin_fd == key->fd);

    struct request_line_st* rl = &(data->client.request_line);
    buffer *b = &rl->rl_to_send_buffer;
    size_t rbytes;
    /* quiero leer en el write buffer de copy */
    uint8_t *write_buffer_ptr = buffer_read_ptr(b, &rbytes);
    printf("rbytes %ld \n", rbytes);
    ssize_t numBytesWritten = send(key->fd, write_buffer_ptr, rbytes,MSG_NOSIGNAL);
    printf("rl write numBytesWritten = %ld\n", numBytesWritten);
    unsigned ret = REQUEST_LINE_WRITE;
    bool error = false;

    if(numBytesWritten < 0){
        ret = ERROR;
    }else if(numBytesWritten == 0){
        printf("send devuelve 0\n");
        // si llega EOF entonces debo quitar OP_WRITE del copy actual y OP_READ del copy_to
        // la conexión no termina ya que puede quedar data en el buffer con dirección contraria
        abort();
    }else{
        // se escribió algo
        buffer_read_adv(b, numBytesWritten);
        printf("%d)Escribi %ld bytes del request line\n",key->fd, numBytesWritten);
        printf("\nWRITE BUFFER\n");
        print_buffer(b);
        rl->rl_to_send_written += numBytesWritten;
        bool can_read = buffer_can_read(b);
        bool finished_writting = rl->rl_to_send_written >= rl->rl_to_send_len;
        if(finished_writting){
            printf("termine de escribir la primera linea \n");
            if (SELECTOR_SUCCESS != selector_set_interest(key->s,data->client_fd, OP_READ))
            {
                error = true;
                goto finally;
            }

            if (SELECTOR_SUCCESS != selector_set_interest(key->s,data->origin_fd, OP_READ))
            {
                error = true;
                goto finally;
            }
            ret = COPY;
        }else if(!finished_writting && can_read){
            printf("no termine de escribir y puedo seguir leyendo\n");
            // no termine de enviar al origin server toda la request line y puedo seguir leyendo del buffer


        }else if(!can_read){
            printf("no termine de escribir y no puedo leer\n");
            error = true;
            goto finally;
        }
            //read first line
           
           
        
      
    }
finally:
    return error ? ERROR : ret;
}   

////////////////////////////////////////////////////////////////////////////////
// REQUEST MESSAGE WRITE
////////////////////////////////////////////////////////////////////////////////

static void request_message_init(const unsigned state,struct selector_key *key){
    struct httpd *data = ATTACHMENT(key);
    struct copy_st *copy = &data->client.copy;
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
}

static struct copy_st *get_copy_from_key(struct selector_key *key){
    struct copy_st *copy = &ATTACHMENT(key)->client.copy;
    return copy->fd == key->fd ? copy : copy->copy_to;
}

static void selector_set_new_interest(struct copy_st* copy,fd_selector s){

    printf("%d) set new interest\n",copy->fd);
    assert(copy->fd > 0);

    fd_interest new_interests = OP_NOOP;

    if((copy->interest & OP_READ) && buffer_can_write(copy->rb)){
        printf("Agrego OP READ  a fd: %d\n", copy->fd);
        new_interests |= OP_READ;
    }else{
         printf("no agrego read\n");
    }
    if((copy->interest & OP_WRITE) && buffer_can_read(copy->wb)){

        printf("Agrego OP_WRITE  a fd: %d\n", copy->fd);
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

    size_t wbytes;
    /* quiero escribir en el read buffer de copy */
    uint8_t *read_buffer_ptr = buffer_write_ptr(copy->rb, &wbytes);
    printf("wbytes = %ld\n", wbytes);
    ssize_t numBytesRead = recv(key->fd, read_buffer_ptr, wbytes,0);
    printf("copy read numBytesRead = %ld\n", numBytesRead);
    unsigned ret = COPY;

   
    if(numBytesRead < 0){
        ret = ERROR;
    }else if(numBytesRead == 0){
        printf("recv devuelve 0\n");
        // si llega EOF entonces debo quitar OP_READ del copy actual y OP_WRITE del copy_to
        // la conexión no termina ya que puede quedar data en el buffer con dirección contraria
        copy->interest &= ~OP_READ;
        shutdown(copy->fd, SHUT_RD);
        copy->copy_to->interest &= ~OP_WRITE;
        shutdown(copy->copy_to->fd, SHUT_WR);

        if(copy->interest == OP_NOOP){
            // una de las partes no puede leer ni enviar más datos
               printf("interest == NOOP\n");
            return DONE;
        }

    }else{
        // se leyó algo
        buffer_write_adv(copy->rb, numBytesRead);
        printf("%d)Escribi %ld bytes\n",key->fd, numBytesRead);
        printf("READ BUFFER\n");
        print_buffer(copy->rb);
        printf("\nWRITE BUFFER\n");
        print_buffer(copy->wb);
    }
    selector_set_new_interest(copy,key->s);
    selector_set_new_interest(copy->copy_to,key->s);
    return ret;
}

static unsigned copy_write(struct selector_key *key){

    printf("COPY_WRITE\n");
    struct copy_st *copy = get_copy_from_key(key);

    size_t rbytes;
    /* quiero leer en el write buffer de copy */
    uint8_t *write_buffer_ptr = buffer_read_ptr(copy->wb, &rbytes);
    printf("rbytes %ld \n", rbytes);
    ssize_t numBytesWritten = send(key->fd, write_buffer_ptr, rbytes,MSG_NOSIGNAL);
    printf("copy write numBytesWritten = %ld\n", numBytesWritten);
    unsigned ret = COPY;

 
    if(numBytesWritten < 0){
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
        buffer_read_adv(copy->wb, numBytesWritten);
        printf("%d)Escribi %ld bytes\n",key->fd, numBytesWritten);
        printf("READ BUFFER\n");
        print_buffer(copy->rb);
        printf("\nWRITE BUFFER\n");
        print_buffer(copy->wb);
    }
    selector_set_new_interest(copy,key->s);
    selector_set_new_interest(copy->copy_to,key->s);
    return ret;

}
