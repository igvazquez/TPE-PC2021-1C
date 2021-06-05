/**
 * main.c - servidor proxy socks concurrente
 *
 * Interpreta los argumentos de lÃ­nea de comandos, y monta un socket
 * pasivo.
 *
 * Todas las conexiones entrantes se manejarÃ¡n en Ã©ste hilo.
 *
 * Se descargarÃ¡ en otro hilos las operaciones bloqueantes (resoluciÃ³n de
 * DNS utilizando getaddrinfo), pero toda esa complejidad estÃ¡ oculta en
 * el selector.
 */
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <signal.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/types.h>   // socket
#include <sys/socket.h>  // socket
#include <netinet/in.h>
#include <netinet/tcp.h>

#include "../include/httpdnio.h"
#include "../include/selector.h"
#include "../include/args.h"
#include "../include/netutils.h"
#include "../include/parser_utils.h"
#include "../include/mime_chars.h"
#include "../include/stdout_writer.h"
#define MAX_SOCKETS 1024

#define STDIN_FILENO 0

#define MAX_WAITING_CONNECTIONS 20

static bool done = false;

static void
sigterm_handler(const int signal) {
    printf("signal %d, cleaning up and exiting\n",signal);
    done = true;
}

int
main(const int argc, const char **argv) {

    parse_args(argc, argv);



    // no tenemos nada que leer de stdin
    close(STDIN_FILENO);

    const char       *err_msg = NULL;
    selector_status   ss      = SELECTOR_SUCCESS;
    fd_selector selector      = NULL;

    // registrar sigterm es util para terminar el programa normalmente.
    // esto ayuda mucho en herramientas como valgrind.
    signal(SIGTERM, sigterm_handler);
    signal(SIGINT,  sigterm_handler);


    //////////////////////////////////////////////// CREATE IP V4 SOCKET ////////////////////////////////////////////////
    //TODO: hacer lo mismo para IPV6 como en tcpEchoAddrInfo.c y guardar la familia del IP usado en el struct httpd
    char *ip;
    unsigned short port = get_port();
    int serverV4 = 0;
    int serverV6 = 0;
    char buff[30];

    if((ip = get_ipv4_addr()) != NULL){
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
         if(inet_pton(AF_INET,ip,&(addr.sin_addr)) < 0){
             err_msg = "failed inet_pton trying to read IPV4";
             goto finally;
         }
        addr.sin_family = AF_INET;
        
        addr.sin_port = htons(port);

        serverV4 = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if(serverV4 < 0) {
            err_msg = "unable to create IPV4 socket";
            goto finally;
        }

        fprintf(stdout, "Listening IPV4 on TCP port %d\n", port);

        // man 7 ip. no importa reportar nada si falla.
        setsockopt(serverV4, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int));
        printf("binding ipv4 : %s\n", sockaddr_to_human(buff, 30, (struct sockaddr *)(&addr)));
        if(bind(serverV4, (struct sockaddr*) &addr, sizeof(addr)) < 0) {
            err_msg = "unable to bind IPV4 socket";
            goto finally;
        }

        if (listen(serverV4, MAX_WAITING_CONNECTIONS) < 0) {
            err_msg = "unable to listen IPV4 socket";
            goto finally;
        }
        //hago que el fd del server socket sea O_NONBLOCK
        if(selector_fd_set_nio(serverV4) == -1) {
          err_msg = "getting server socket flags";
          goto finally;
        }
    }

    if((ip = get_ipv6_addr()) != NULL){
            struct sockaddr_in6 addr6;
            memset(&addr6, 0, sizeof(addr6));

            if(inet_pton(AF_INET6,ip,&(addr6.sin6_addr)) < 0){
                err_msg = "failed inet_pton trying to read IPV6";
                goto finally;
            }
            addr6.sin6_family = AF_INET6;
            addr6.sin6_port        = htons(port);

            serverV6 = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
            if(serverV6 < 0) {
                err_msg = "unable to create IPV6 socket";
                goto finally;
            }

            fprintf(stdout, "Listening IPV6 on TCP port %d\n", port);

            // man 7 ip. no importa reportar nada si falla.
            setsockopt(serverV6, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int));

            printf("binding ipv6 : %s\n", sockaddr_to_human(buff, 30, (struct sockaddr *)(&addr6)));
            if(bind(serverV6, (struct sockaddr*) &addr6, sizeof(addr6)) < 0) {
                err_msg = "unable to bind IPV6 socket";
                goto finally;
            }

            if (listen(serverV6, MAX_WAITING_CONNECTIONS) < 0) {
                err_msg = "unable to listen IPV4 socket";
                goto finally;
            }
            //hago que el fd del server socket sea O_NONBLOCK
            if(selector_fd_set_nio(serverV6) == -1) {
                err_msg = "getting server socket flags";
                goto finally;
            }
    }

   
 
    
    const struct selector_init conf = {
        .signal = SIGALRM,
        .select_timeout = {
            .tv_sec  = 10,
            .tv_nsec = 0,
        },
    };
    
    if(0 != selector_init(&conf)) {
        err_msg = "initializing selector";
        goto finally;
    }
    
    selector = selector_new(MAX_SOCKETS);
    if(selector == NULL) {
        err_msg = "unable to create selector";
        goto finally;
    }
    const struct fd_handler httpd = {
        .handle_read       = httpd_passive_accept,
        .handle_write      = NULL,
        .handle_close      = NULL, // nada que liberar
    };
    printf("register serverv4 %d\n", serverV4);
    ss = selector_register(selector, serverV4, &httpd,
                                              OP_READ, NULL);
    if(ss != SELECTOR_SUCCESS) {
        err_msg = "registering fd IPV4";
        goto finally;
    }
      printf("register serverv6 %d\n", serverV6);
    ss = selector_register(selector, serverV6, &httpd,
                                              OP_READ, NULL);
    if(ss != SELECTOR_SUCCESS) {
        err_msg = "registering fd IPV6";
        goto finally;
    }
/////////////////////////////////////////////////////////////////
//  NON BLOCKING STD OUT REGISTERING
/////////////////////////////////////////////////////////////////
    stdout_writer_initialize(selector);
    const struct fd_handler stdout_handler = {
        .handle_read       = NULL,
        .handle_write      = stdout_write,
        .handle_close      = NULL, // nada que liberar
    };

    // Setting STDOUT has non blocking
    if (selector_fd_set_nio(1) == -1)
    {
        err_msg = "setting stdout as non-blocking";
        goto finally;
    }

    ss = selector_register(selector, 1, &stdout_handler,OP_READ, get_stdout_writer_data);
    if(ss != SELECTOR_SUCCESS) {
        err_msg = "registering fd STDOUT";
        goto finally;
    }

////////////////////////////////////////////////////////////////

    for(;!done;) {
        err_msg = NULL;
        ss = selector_select(selector);
        if(ss != SELECTOR_SUCCESS) {
            err_msg = "serving";
            goto finally;
        }
    }
    if(err_msg == NULL) {
        err_msg = "closing";
    }

    int ret = 0;
finally:
    if(ss != SELECTOR_SUCCESS) {
        fprintf(stderr, "%s: %s\n", (err_msg == NULL) ? "": err_msg,
                                  ss == SELECTOR_IO
                                      ? strerror(errno)
                                      : selector_error(ss));
        ret = 2;
    } else if(err_msg) {
        perror(err_msg);
        ret = 1;
    }
    if(selector != NULL) {
        selector_destroy(selector);
    }
    selector_close();

    //socksv5_pool_destroy();

    if(serverV4 >= 0) {
        close(serverV4);
    }
    if(serverV6 >= 0) {
        close(serverV6);
    }
    return ret;
}

