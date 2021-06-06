#include <stdio.h>     /* for printf */
#include <stdlib.h>    /* for exit */
#include <limits.h>    /* LONG_MIN et al */
#include <string.h>    /* memset */
#include <errno.h>
#include <getopt.h>
#include <arpa/inet.h>
#include "../include/args.h"


struct httpdargs * args;

static unsigned short
port(const char *s) {
     char *end     = 0;
     const long sl = strtol(s, &end, 10);

     if (end == s|| '\0' != *end
        || ((LONG_MIN == sl || LONG_MAX == sl) && ERANGE == errno)
        || sl < 0 || sl > USHRT_MAX) {
         fprintf(stderr, "port should in in the range of 1-65536: %s\n", s);
         exit(1);
         return 1;
     }
     return (unsigned short)sl;
}

static void
user(char *s, struct users *user) {
    char *p = strchr(s, ':');
    if(p == NULL) {
        fprintf(stderr, "password not found\n");
        exit(1);
    } else {
        *p = 0;
        p++;
        user->name = s;
        user->pass = p;
    }

}

static void
version(void) {
    fprintf(stderr, "httpd version 0.0\n"
                    "ITBA Protocolos de ComunicaciÃ³n 2020/1 -- Grupo 08\n"
                    "AQUI VA LA LICENCIA\n");
}

static void
usage(const char *progname) {
    fprintf(stderr,
        "Usage: %s [OPTION]...\n"
        "\n"
        "   -h               Imprime la ayuda y termina.\n"
        "   -l <SOCKS addr>  DirecciÃ³n donde servirÃ¡ el proxy SOCKS.\n"
        "   -L <conf  addr>  DirecciÃ³n donde servirÃ¡ el servicio de management.\n"
        "   -p <SOCKS port>  Puerto entrante conexiones SOCKS.\n"
        "   -P <conf port>   Puerto entrante conexiones configuracion\n"
        "   -u <name>:<pass> Usuario y contraseÃ±a de usuario que puede usar el proxy. Hasta 10.\n"
        "   -v               Imprime informaciÃ³n sobre la versiÃ³n versiÃ³n y termina.\n"
        "\n"
        "   --doh-ip    <ip>    \n"
        "   --doh-port  <port>  XXX\n"
        "   --doh-host  <host>  XXX\n"
        "   --doh-path  <host>  XXX\n"
        "   --doh-query <host>  XXX\n"

        "\n",
        progname);
    exit(1);
}

void 
parse_args(const int argc,const char **argv) {
    args = (struct httpdargs *) malloc(sizeof(*args));
    if(args == NULL){
        fprintf(stderr, "unable to allocate memory for args struct: ");
        exit(1);
    }
    memset(args, 0, sizeof(*args)); // sobre todo para setear en null los punteros de users

    args->httpd_v4_addr = "0.0.0.0";
    args->httpd_v6_addr = "::1";
    args->httpd_port = 1080;

    args->mng_addr   = "127.0.0.1";
    args->mng_port   = 8080;

    args->disectors_enabled = true;

    args->doh.host = "localhost";
    args->doh.ip   = "127.0.0.1";
    args->doh.port = 8053;
    args->doh.path = "/getnsrecord";
    args->doh.query = "?dns=";

    int c;
    int nusers = 0;

    while (true) {
        int option_index = 0;
        static struct option long_options[] = {
            { "doh-ip",    required_argument, 0, 0xD001 },
            { "doh-port",  required_argument, 0, 0xD002 },
            { "doh-host",  required_argument, 0, 0xD003 },
            { "doh-path",  required_argument, 0, 0xD004 },
            { "doh-query", required_argument, 0, 0xD005 },
            { 0,           0,                 0, 0 }
        };
        struct sockaddr_in aux_ipv4_addr;
        int i4pton_ret;
        int i6pton_ret;
        struct sockaddr_in6 aux_ipv6_addr;
        c = getopt_long(argc, (char**)argv, "hl:L:Np:P:u:v", long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
            case 'h':
                usage(argv[0]);
                break;
            case 'l':
                
              
                if((i4pton_ret = inet_pton(AF_INET,optarg,&(aux_ipv4_addr.sin_addr))) == 1){
                    // La ip ingresada es ipv4
                    args->httpd_v6_addr = NULL;

                }else if(i4pton_ret == 0){
                   
                  
                    if((i6pton_ret=inet_pton(AF_INET6,optarg,&(aux_ipv6_addr.sin6_addr))) == 1){
                        // La ip ingresada es ipv6
                        args->httpd_v4_addr = NULL;
                    }else if(i6pton_ret < 0){
                            // ERROR IPV6
                            fprintf(stderr, "failed inet_pton trying to read IPV6 with errno: %d\n",errno);
                            exit(1);
                    
                    }
                }else{
                    // ERROR IPV4
                    fprintf(stderr, "failed inet_pton trying to read IPV4 with errno: %d\n",errno);
                    exit(1);
                }
              
              
                break;
            case 'L':
                args->mng_addr = optarg;
                break;
            case 'N':
                args->disectors_enabled = false;
                break;
            case 'p':
                args->httpd_port = port(optarg);
                break;
            case 'P':
                args->mng_port   = port(optarg);
                break;
            case 'u':
                if(nusers >= MAX_USERS) {
                    fprintf(stderr, "maximun number of command line users reached: %d.\n", MAX_USERS);
                    exit(1);
                } else {
                    user(optarg, args->users + nusers);
                    nusers++;
                }
                break;
            case 'v':
                version();
                exit(0);
                break;
            case 0xD001:
                args->doh.ip = optarg;
                break;
            case 0xD002:
                args->doh.port = port(optarg);
                break;
            case 0xD003:
                args->doh.host = optarg;
                break;
            case 0xD004:
                args->doh.path = optarg;
                break;
            case 0xD005:
                args->doh.query = optarg;
                break;
            default:
                fprintf(stderr, "unknown argument %d.\n", c);
                exit(1);
        }
    }
    if (optind < argc) {
        fprintf(stderr, "argument not accepted: ");
        while (optind < argc) {
            fprintf(stderr, "%s ", argv[optind++]);
        }
        fprintf(stderr, "\n");
        exit(1);
    }
}


// GETTERS
char *get_ipv4_addr(){
    return args->httpd_v4_addr;
}
char *get_ipv6_addr(){
    return args->httpd_v6_addr;
}
unsigned short get_port(){
    return args->httpd_port;
}
bool get_disectors_enabled(){
    return args->disectors_enabled;
}