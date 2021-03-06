#ifndef ARGS_H_kFlmYm1tW9p5npzDr2opQJ9jM8
#define ARGS_H_kFlmYm1tW9p5npzDr2opQJ9jM8

#include <stdbool.h>

#define MAX_USERS 10


struct doh_args {
    char           *host;
    char           *ip;
    unsigned short  port;
    char           *path;
    char           *query;
};

struct httpdargs {
    char           *httpd_v4_addr;
    char           *httpd_v6_addr;
    unsigned short  httpd_port;

    char *          mng_addr;
    unsigned short  mng_port;

    bool            disectors_enabled;

    struct doh_args      doh;

};

/**
 * Interpreta la linea de comandos (argc, argv) llenando
 * args con defaults o la seleccion humana. Puede cortar
 * la ejecuciÃ³n.
 */
void 
parse_args(const int argc,const char **argv);

char *get_ipv4_addr();
char *get_ipv6_addr();
unsigned short get_port();
bool get_disectors_enabled();


struct doh_args get_doh_info();
void free_args();
#endif
