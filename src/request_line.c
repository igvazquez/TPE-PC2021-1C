#include "../include/request_line.h"
#include "../include/parser.h"
#include "../include/parser_utils.h"
#include "../include/mime_chars.h"
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
/*
#define UNKOWN_ADDR_TYPE (DOMAIN_NAME | IPV4 | IPV6)
#define DOMAIN_NAME_OR_IPV4 (DOMAIN_NAME | IPV4)


static enum start_line_state scheme(struct parser *parser, uint8_t c);
static enum start_line_state host(struct start_line * sl, uint8_t c);

static enum start_line_state port(struct start_line *sl, uint8_t c);
static enum start_line_state path(struct start_line *sl, uint8_t c);
*/


enum state
{
    METHOD0,
    METHOD,
    SCHEME0,
    SCHEME1,
    SCHEME2,
    SCHEME3,
    SCHEME4,
    SCHEME5,
    SCHEME6,
    HOST0,
    FQDN_OR_IPV4,
    IPV60,
    IPV6,
    IPV6_END,
    PORT0,
    PORT,
    PATH0,
    PATH,
    QUERY0,
    QUERY,
    FRAGMENT0,
    FRAGMENT,
    HTTP_VERSION_NAME0,
    HTTP_VERSION_NAME1,
    HTTP_VERSION_NAME2,
    HTTP_VERSION_NAME3,
    HTTP_VERSION_NAME4,
    HTTP_VERSION_MAJOR,
    HTTP_VERSION_DOT,
    HTTP_VERSION_MINOR,
    CR,
    CRLF,
    DONE,
    ERROR,

};

///////////////////////////////////////////////////////////////////////////////
// Acciones

static void
method(struct parser_event *ret, const uint8_t c) {
    ret->type    = RL_METHOD;
    ret->n       = 1;
    ret->data[0] = c;
}

static void
method_end(struct parser_event *ret, const uint8_t c) {
    ret->type    = RL_METHOD_END;
    ret->n       = 1;
    ret->data[0] = c;
}


static void
scheme(struct parser_event *ret, const uint8_t c) {
    ret->type    = RL_SCHEME;
    ret->n       = 1;
    ret->data[0] = c;
}

static void
ipv6_0(struct parser_event *ret, const uint8_t c) {
    ret->type    = RL_IPV6_0;
    ret->n       = 1;
    ret->data[0] = c;
}


static void
ipv6(struct parser_event *ret, const uint8_t c) {
    ret->type    = RL_IPV6;
    ret->n       = 1;
    ret->data[0] = c;
}


static void
host(struct parser_event *ret, const uint8_t c) {
    ret->type    = RL_HOST;
    ret->n       = 1;
    ret->data[0] = c;
}


static void
host_end(struct parser_event *ret, const uint8_t c) {
    ret->type    = RL_HOST_END;
    ret->n       = 1;
    ret->data[0] = c;
}


static void
port(struct parser_event *ret, const uint8_t c) {
    ret->type    = RL_PORT;
    ret->n       = 1;
    ret->data[0] = c;
}


static void
origin_form(struct parser_event *ret, const uint8_t c) {
    ret->type    = RL_ORIGIN_FORM;
    ret->n       = 1;
    ret->data[0] = c;
}

static void
origin_form_end(struct parser_event *ret, const uint8_t c) {
    ret->type    = RL_ORIGIN_FORM_END;
    ret->n       = 1;
    ret->data[0] = c;
}




static void
http_name(struct parser_event *ret, const uint8_t c) {
    ret->type    = RL_HTTP_NAME;
    ret->n       = 1;
    ret->data[0] = c;
}

static void
http_version_major(struct parser_event *ret, const uint8_t c) {
    ret->type    = RL_HTTP_VERSION_MAJOR;
    ret->n       = 1;
    ret->data[0] = c;
}

static void
http_version_minor(struct parser_event *ret, const uint8_t c) {
    ret->type    = RL_HTTP_VERSION_MINOR;
    ret->n       = 1;
    ret->data[0] = c;
}


static void
unexpected(struct parser_event *ret, const uint8_t c) {
    ret->type    = RL_UNEXPECTED;
    ret->n       = 1;
    ret->data[0] = c;
}

static void
wait(struct parser_event *ret, const uint8_t c) {
    ret->type    = RL_WAIT;
    ret->n       = 0;
}

static void
done(struct parser_event *ret, const uint8_t c) {
    ret->type    = RL_DONE;
    ret->n       = 0;
}

///////////////////////////////////////////////////////////////////////////////
// Transiciones
static const struct parser_state_transition ST_METHOD0[] =  {
    {.when = ' ',        .dest = ERROR,         .act1 = unexpected,},
    {.when = TOKEN_TCHAR,  .dest = METHOD,         .act1 = method,},
    {.when = ANY,        .dest = ERROR,         .act1 = unexpected,},
};


static const struct parser_state_transition ST_METHOD[] =  {
    {.when = ' ',        .dest = SCHEME0,         .act1 = method_end,},
    {.when = TOKEN_TCHAR,  .dest = METHOD,         .act1 = method,},
    {.when = ANY,        .dest = ERROR,         .act1 = unexpected,},
};

static const struct parser_state_transition ST_SCHEME0[] =  {
    {.when = 'h',        .dest = SCHEME1,         .act1 = scheme,},
    {.when = ANY,        .dest = ERROR,         .act1 = unexpected,},
};
static const struct parser_state_transition ST_SCHEME1[] =  {
    {.when = 't',        .dest = SCHEME2,         .act1 = scheme,},
    {.when = ANY,        .dest = ERROR,         .act1 = unexpected,},
};

static const struct parser_state_transition ST_SCHEME2[] =  {
    {.when = 't',        .dest = SCHEME3,         .act1 = scheme,},
    {.when = ANY,        .dest = ERROR,         .act1 = unexpected,},
};

static const struct parser_state_transition ST_SCHEME3[] =  {
    {.when = 'p',        .dest = SCHEME4,         .act1 = scheme,},
    {.when = ANY,        .dest = ERROR,         .act1 = unexpected,},
};

static const struct parser_state_transition ST_SCHEME4[] =  {
    {.when = ':',        .dest = SCHEME5,         .act1 = scheme,},
    {.when = ANY,        .dest = ERROR,         .act1 = unexpected,},
};

static const struct parser_state_transition ST_SCHEME5[] =  {
    {.when = '/',        .dest = SCHEME6,         .act1 = scheme,},
    {.when = ANY,        .dest = ERROR,         .act1 = unexpected,},
};

static const struct parser_state_transition ST_SCHEME6[] =  {
    {.when = '/',        .dest = HOST0,         .act1 = scheme,},
    {.when = ANY,        .dest = ERROR,         .act1 = unexpected,},
};

static const struct parser_state_transition ST_HOST0[] =  {
    {.when = TOKEN_UNRESERVED,        .dest = FQDN_OR_IPV4,         .act1 = host,},
    {.when = TOKEN_SUB_DELIMS,        .dest = FQDN_OR_IPV4,         .act1 = host,},
    {.when = '[',        .dest = IPV60,         .act1 = ipv6_0,},
    {.when = ANY,        .dest = ERROR,         .act1 = unexpected,},
};

static const struct parser_state_transition ST_FQDN_OR_IPV4[] =  {
    {.when = TOKEN_UNRESERVED,        .dest = FQDN_OR_IPV4,         .act1 = host,},
    {.when = TOKEN_SUB_DELIMS,        .dest = FQDN_OR_IPV4,         .act1 = host,},
    {.when = ':',        .dest = PORT,         .act1 = wait,},
    {.when = '/',        .dest = PATH0,         .act1 = host_end,.act2 = origin_form},
    {.when = '?',        .dest = QUERY0,         .act1 = host_end,.act2 = origin_form},
    {.when = '#',        .dest = FRAGMENT0,         .act1 = host_end,.act2 = origin_form},
    {.when = ' ',        .dest = HTTP_VERSION_NAME0,         .act1 = host_end,},
    {.when = ANY,        .dest = ERROR,         .act1 = unexpected,},
};
static const struct parser_state_transition ST_IPV60[] =  {
    {.when = TOKEN_HEXA,        .dest = IPV6,         .act1 = host,},
    {.when = ':',        .dest = IPV6,         .act1 = host,},
    {.when = ANY,        .dest = ERROR,         .act1 = unexpected,},
};

static const struct parser_state_transition ST_IPV6[] =  {
    {.when = TOKEN_HEXA,        .dest = IPV6,         .act1 = ipv6,},
    {.when = ':',        .dest = IPV6,         .act1 = ipv6,},
    {.when = ']',        .dest = IPV6_END,         .act1 = host_end,},
    {.when = ANY,        .dest = ERROR,         .act1 = unexpected,},
};


static const struct parser_state_transition ST_IPV6_END[] =  {
    {.when = ':',        .dest = PORT0,         .act1 = wait,},
    {.when = '/',        .dest = PATH0,         .act1 = host_end,.act2 = origin_form},
    {.when = '?',        .dest = QUERY0,         .act1 = host_end,.act2 = origin_form},
    {.when = '#',        .dest = FRAGMENT0,         .act1 = host_end,.act2 = origin_form},
    {.when = ' ',        .dest = HTTP_VERSION_NAME0,         .act1 = host_end,},
    {.when = ANY,        .dest = ERROR,         .act1 = unexpected,},
};


static const struct parser_state_transition ST_PORT0[] =  {
    {.when = TOKEN_DIGIT,        .dest = PORT,         .act1 = port,},
   // {.when = '@',        .dest = HOST0,         .act1 = host,},
    {.when = ANY,        .dest = ERROR,         .act1 = unexpected,},
};


static const struct parser_state_transition ST_PORT[] =  {
    {.when = TOKEN_DIGIT,        .dest = PORT,         .act1 = port,},
    {.when = '/',        .dest = PATH0,         .act1 = host_end,.act2 = origin_form},
    {.when = '?',        .dest = QUERY0,         .act1 = host_end,.act2 = origin_form},
    {.when = '#',        .dest = FRAGMENT0,         .act1 = host_end,.act2 = origin_form},
    {.when = ' ',        .dest = HTTP_VERSION_NAME0,         .act1 = host_end,},
    {.when = ANY,        .dest = ERROR,         .act1 = unexpected,},
};



static const struct parser_state_transition ST_PATH0[] =  {
    {.when = ' ',        .dest = HTTP_VERSION_NAME0,         .act1 = origin_form_end,},
    {.when = TOKEN_UNRESERVED,        .dest = PATH,         .act1 = origin_form,},
    {.when = TOKEN_SUB_DELIMS,        .dest = PATH,         .act1 = origin_form,},
    {.when = '@',        .dest = PATH,         .act1 = origin_form,},
    {.when = ':',        .dest = PATH,         .act1 = origin_form,},
    {.when = ANY,        .dest = ERROR,         .act1 = unexpected,},
};

static const struct parser_state_transition ST_PATH[] =  {
    {.when = ' ',        .dest = HTTP_VERSION_NAME0,         .act1 = origin_form_end,},
    {.when = '/',        .dest = PATH0,         .act1 = origin_form,},
    {.when = TOKEN_UNRESERVED,        .dest = PATH,         .act1 = origin_form,},
    {.when = TOKEN_SUB_DELIMS,        .dest = PATH,         .act1 = origin_form,},
    {.when = '@',        .dest = PATH,         .act1 = origin_form,},
    {.when = ':',        .dest = PATH,         .act1 = origin_form,},
    {.when = '?',        .dest = QUERY0,         .act1 = origin_form,},
    {.when = '#',        .dest = FRAGMENT0,         .act1 = origin_form,},
    {.when = ANY,        .dest = ERROR,         .act1 = unexpected,},
};


static const struct parser_state_transition ST_QUERY0[] =  {
    {.when = ' ',        .dest = HTTP_VERSION_NAME0,         .act1 = origin_form_end,},
    {.when = TOKEN_UNRESERVED,        .dest = QUERY,         .act1 = origin_form,},
    {.when = TOKEN_SUB_DELIMS,        .dest = QUERY,         .act1 = origin_form,},
    {.when = '/',        .dest = QUERY,         .act1 = origin_form,},
    {.when = ANY,        .dest = ERROR,         .act1 = unexpected,},
};

static const struct parser_state_transition ST_QUERY[] =  {
    {.when = ' ',        .dest = HTTP_VERSION_NAME0,         .act1 = origin_form_end,},
    {.when = '#',        .dest = FRAGMENT0,         .act1 = origin_form,},
    {.when = TOKEN_UNRESERVED,        .dest = QUERY,         .act1 = origin_form,},
    {.when = TOKEN_SUB_DELIMS,        .dest = QUERY,         .act1 = origin_form,},
    {.when = '/',        .dest = QUERY,         .act1 = origin_form,},
    {.when = ANY,        .dest = ERROR,         .act1 = unexpected,},
};


static const struct parser_state_transition ST_FRAGMENT0[] =  {
    {.when = ' ',        .dest = HTTP_VERSION_NAME0,         .act1 = origin_form_end,},
    {.when = TOKEN_UNRESERVED,        .dest = FRAGMENT,         .act1 = origin_form,},
    {.when = TOKEN_SUB_DELIMS,        .dest = FRAGMENT,         .act1 = origin_form,},
    {.when = '?',        .dest = FRAGMENT,         .act1 = origin_form,},
    {.when = '/',        .dest = FRAGMENT,         .act1 = origin_form,},
    {.when = ANY,        .dest = ERROR,         .act1 = unexpected,},
};


static const struct parser_state_transition ST_FRAGMENT[] =  {
    {.when = ' ',        .dest = HTTP_VERSION_NAME0,         .act1 = origin_form_end,},
    {.when = TOKEN_UNRESERVED,        .dest = FRAGMENT,         .act1 = origin_form,},
    {.when = TOKEN_SUB_DELIMS,        .dest = FRAGMENT,         .act1 = origin_form,},
    {.when = '?',        .dest = FRAGMENT,         .act1 = origin_form,},
    {.when = '/',        .dest = FRAGMENT,         .act1 = origin_form,},
    {.when = ANY,        .dest = ERROR,         .act1 = unexpected,},
};

static const struct parser_state_transition ST_HTTP_VERSION_NAME0[] =  {
    {.when = 'H',        .dest = HTTP_VERSION_NAME1,         .act1 = http_name,},
    {.when = ANY,        .dest = ERROR,         .act1 = unexpected,},
};
static const struct parser_state_transition ST_HTTP_VERSION_NAME1[] =  {
    {.when = 'T',        .dest = HTTP_VERSION_NAME2,         .act1 = http_name,},
    {.when = ANY,        .dest = ERROR,         .act1 = unexpected,},
};
static const struct parser_state_transition ST_HTTP_VERSION_NAME2[] =  {
    {.when = 'T',        .dest = HTTP_VERSION_NAME3,         .act1 = http_name,},
    {.when = ANY,        .dest = ERROR,         .act1 = unexpected,},
};
static const struct parser_state_transition ST_HTTP_VERSION_NAME3[] =  {
    {.when = 'P',        .dest = HTTP_VERSION_NAME4,         .act1 = http_name,},
    {.when = ANY,        .dest = ERROR,         .act1 = unexpected,},
};
static const struct parser_state_transition ST_HTTP_VERSION_NAME4[] =  {
    {.when = '/',        .dest = HTTP_VERSION_MAJOR,         .act1 = http_name,},
    {.when = ANY,        .dest = ERROR,         .act1 = unexpected,},
};
static const struct parser_state_transition ST_HTTP_VERSION_MAJOR[] =  {
    {.when = TOKEN_DIGIT,        .dest = HTTP_VERSION_DOT,         .act1 = http_version_major,},
    {.when = ANY,        .dest = ERROR,         .act1 = unexpected,},
};
static const struct parser_state_transition ST_HTTP_VERSION_DOT[] =  {
    {.when = '.',        .dest = HTTP_VERSION_MINOR,         .act1 = wait,},
    {.when = ANY,        .dest = ERROR,         .act1 = unexpected,},
};
static const struct parser_state_transition ST_HTTP_VERSION_MINOR[] =  {
    {.when = TOKEN_DIGIT,        .dest = CR,         .act1 = http_version_minor,},
    {.when = ANY,        .dest = ERROR,         .act1 = unexpected,},
};

static const struct parser_state_transition ST_CR[] =  {
    {.when = '\r',        .dest = CRLF,         .act1 = wait,},
    {.when = ANY,        .dest = ERROR,         .act1 = unexpected,},
};

static const struct parser_state_transition ST_CRLF[] =  {
    {.when = '\n',        .dest = DONE,         .act1 = done,},
    {.when = ANY,        .dest = ERROR,         .act1 = unexpected,},
};

static const struct parser_state_transition ST_DONE[] =  {
    {.when = ANY,        .dest = ERROR,         .act1 = unexpected,},
};

static const struct parser_state_transition ST_ERROR[] =  {
    {.when = ANY,        .dest = ERROR,         .act1 = unexpected,},
};


///////////////////////////////////////////////////////////////////////////////
// Declaración formal
static const struct parser_state_transition *states[] =
{
    ST_METHOD0,
    ST_METHOD,
    ST_SCHEME0,
    ST_SCHEME1,
    ST_SCHEME2,
    ST_SCHEME3,
    ST_SCHEME4,
    ST_SCHEME5,
    ST_SCHEME6,
    ST_HOST0,
    ST_FQDN_OR_IPV4,
    ST_IPV60,
    ST_IPV6,
    ST_IPV6_END,
    ST_PORT0,
    ST_PORT,
    ST_PATH0,
    ST_PATH,
    ST_QUERY0,
    ST_QUERY,
    ST_FRAGMENT0,
    ST_FRAGMENT,
    ST_HTTP_VERSION_NAME0,
    ST_HTTP_VERSION_NAME1,
    ST_HTTP_VERSION_NAME2,
    ST_HTTP_VERSION_NAME3,
    ST_HTTP_VERSION_NAME4,
    ST_HTTP_VERSION_MAJOR,
    ST_HTTP_VERSION_DOT,
    ST_HTTP_VERSION_MINOR,
    ST_CR,
    ST_CRLF,
    ST_DONE,
    ST_ERROR,

};
#define N(x) (sizeof(x)/sizeof((x)[0]))

static const size_t states_n [] = {
    N(ST_METHOD0),
    N(ST_METHOD),
    N(ST_SCHEME0),
    N(ST_SCHEME1),
    N(ST_SCHEME2),
    N(ST_SCHEME3),
    N(ST_SCHEME4),
    N(ST_SCHEME5),
    N(ST_SCHEME6),
    N(ST_PORT0),
    N(ST_HOST0),
    N(ST_FQDN_OR_IPV4),
    N(ST_IPV60),
    N(ST_IPV6),
    N(ST_IPV6_END),
    N(ST_PORT),
    N(ST_PATH0),
    N(ST_PATH),
    N(ST_QUERY0),
    N(ST_QUERY),
    N(ST_FRAGMENT0),
    N(ST_FRAGMENT),
    N(ST_HTTP_VERSION_NAME0),
    N(ST_HTTP_VERSION_NAME1),
    N(ST_HTTP_VERSION_NAME2),
    N(ST_HTTP_VERSION_NAME3),
    N(ST_HTTP_VERSION_NAME4),
    N(ST_HTTP_VERSION_MAJOR),
    N(ST_HTTP_VERSION_DOT),
    N(ST_HTTP_VERSION_MINOR),
    N(ST_CR),
    N(ST_CRLF),
    N(ST_DONE),
    N(ST_ERROR),
};

static struct parser_definition definition = {
    .states_count = N(states),
    .states       = states,
    .states_n     = states_n,
    .start_state  = METHOD0,
};

const struct parser_definition * request_line_parser_definition(void){
    return &definition;
}





void request_line_parser_init(struct request_line_parser *parser)
{
   assert(parser != NULL);
   parser->rl_parser = parser_init(init_char_class(), request_line_parser_definition());
   if (parser->rl_parser == NULL)
   {
       printf("parser_init returned null");
       abort();
    }
   parser->parsed_info.port = 0; 
   parser->parsed_info.method_counter = 0;
   parser->parsed_info.host_counter = 0;
   parser->parsed_info.origin_form_counter = 0;
   parser->parsed_info.host_type = domain_or_ipv4_addr; // DEFAULT

 
}


static void set_authority_form(struct parser* p){
    assert(p != NULL);
    parser_set_state(p, HOST0);
}

static bool process_event(const struct parser_event * e,request_line_parser *parser){
    struct parsed_info *parsed_info= &parser->parsed_info;
    switch (e->type)
    {
    case RL_METHOD:
        if(parsed_info->method_counter > MAX_METHOD_LENGTH)
            return true;
        parsed_info->method_buffer[(parsed_info->method_counter)++] = e->data[0];
        break;
    case RL_METHOD_END:
        parsed_info->method_buffer[parsed_info->method_counter] = '\0';
        if(strcmp(parsed_info->method_buffer,"CONNECT") == 0){
            set_authority_form(parser->rl_parser);
        }
        break;
    case RL_HOST:
            if(parsed_info->host_counter > MAX_FQDN_LENGTH)
                return true;
            parsed_info->host.domain_or_ipv4_buffer[(parsed_info->host_counter)++] = e->data[0];
        break;
    case RL_HOST_END:
        if(parsed_info->host_type == domain_or_ipv4_addr){
            if(parsed_info->host_counter > MAX_FQDN_LENGTH)
                return true;
            parsed_info->host.domain_or_ipv4_buffer[parsed_info->host_counter] = '\0';

        }else{
            if(parsed_info->host_counter > MAX_IPV6_LENGTH)
                return true;
            parsed_info->host.ipv6_buffer[parsed_info->host_counter] = '\0';
        }
        break;
    case RL_PORT:
        parsed_info->port *= 10;
        parsed_info->port += (e->data[0] - '0');
        break;
    case RL_IPV6_0:
        parsed_info->host_type = ipv6_addr;
        break;
    case RL_IPV6:
        if(parsed_info->host_counter > MAX_IPV6_LENGTH)
            return true;
        parsed_info->host.ipv6_buffer[(parsed_info->host_counter)++] = e->data[0];
        break;
    case RL_ORIGIN_FORM:
        if(parsed_info->origin_form_counter > MAX_ORIGIN_FORM)
            return true;
        parsed_info->origin_form_buffer[(parsed_info->origin_form_counter)++] = e->data[0];
        break;
    case RL_ORIGIN_FORM_END:
        if(parsed_info->origin_form_counter > MAX_ORIGIN_FORM)
            return true;
        parsed_info->origin_form_buffer[parsed_info->origin_form_counter] =  '\0';
        break;
    case RL_HTTP_VERSION_MAJOR:
        parsed_info->version_major = e->data[0] - '0';
        break;
    case RL_HTTP_VERSION_MINOR:
        parsed_info->version_minor = e->data[0] - '0';  
        break;
    case RL_WAIT:
        // nada
        break;
        default:
        break;
    }
    return false;
}


static void fill_request_line_data(struct request_line_parser * parser,bool *error){
    printf("\nfill request line data\n");
    struct request_line *rl = parser->request_line;
    struct parsed_info pi = parser->parsed_info;
    int i6pton_ret, i4pton_ret;
    switch(pi.host_type){
        case ipv6_addr:
           
            printf("Probando si ipv6: %s es valida\n", pi.host.ipv6_buffer);
            if((i6pton_ret=inet_pton(AF_INET6,pi.host.ipv6_buffer,&(rl->request_target.host.ipv6))) == 1){
                // La ip ingresada es ipv6
                rl->request_target.host_type = ipv6_addr_t;
            }else if(i6pton_ret <= 0){
                // la ipv6 no es correcta o inet_pton falló
                //TODO: probablemente el bool * error en todas estas funciones deba cambiar por una enum para luego devolver una respuesta de error custom
                *error = true;
                printf("Not ipv6\n");
                goto finally;
            }
            break;
        case domain_or_ipv4_addr:
            
            printf("Probando si ipv4: %s es valida\n", pi.host.domain_or_ipv4_buffer);
            if((i4pton_ret=inet_pton(AF_INET,pi.host.domain_or_ipv4_buffer,&(rl->request_target.host.ipv4))) == 1){
                    // La ip ingresada es ipv6
                rl->request_target.host_type = ipv4_addr_t;
            }else if(i4pton_ret == 0){
                printf("%s es un domain name\n", pi.host.domain_or_ipv4_buffer);
                // la ipv6 no es correcta => considero que es un domain name
                 rl->request_target.host_type = domain_addr_t;
                 memcpy(rl->request_target.host.domain, pi.host.domain_or_ipv4_buffer, pi.host_counter+1);
                 //TODO: probablemente el bool * error en todas estas funciones deba cambiar por una enum para luego devolver una respuesta de error custom
              
            }else{
                // inet_pton falló
                 *error = true;
                 goto finally;
            }
            break;
        default:
            *error = true;
            return;
            break;
    }
    
    memcpy(rl->request_target.origin_form, pi.origin_form_buffer, pi.origin_form_counter+1);

    if(pi.port != 0){
       
        rl->request_target.port = htons(pi.port);
    }else{
       
        rl->request_target.port = htons(DEFAULT_HTTP_PORT);
    }

    
    uint8_t version_major = pi.version_major;
    if(pi.version_major == 1){
         rl->version_major = version_major;
    }else{
        *error = true;
        goto finally;
    }
    uint8_t version_minor = pi.version_minor;
    if(version_minor <= 1){
         rl->version_minor = version_minor;
    }else{
        *error = true;
        goto finally;
    }

    memcpy(rl->method, pi.method_buffer, pi.method_counter+1);

    //TODO ver que onda el userinfo
   

finally:
    return;
}




bool request_line_parser_consume(buffer *buffer, request_line_parser *parser, bool *error){

    assert(parser != NULL && buffer != NULL);
    const struct parser_event *e;

    while (buffer_can_read(buffer))
    {
        uint8_t c = buffer_read(buffer);
        printf("Leo: %c\n", c);
        e = parser_feed(parser->rl_parser, c);
        printf("Estado: %d\n", e->type);
        do{
            if (request_line_is_done(e->type, error))
            {
                printf("request message done - error: %d\n", *error);
                if(*error == false){
                    fill_request_line_data(parser, error);
                }
                return true;
            }
            if((*error = process_event(e,parser))){
                //dio error
                return true;
            }
            e = e->next;
        } while (e != NULL);
    }
    return false;
}

void request_line_parser_reset(struct request_line_parser *parser){
   parser->parsed_info.port = 0; 
   parser->parsed_info.method_counter = 0;
   parser->parsed_info.host_counter = 0;
   parser->parsed_info.origin_form_counter = 0;
   parser->parsed_info.host_type = domain_or_ipv4_addr; // DEFAULT
   parser_reset(parser->rl_parser);
}



bool request_line_is_done(enum request_line_event_type type, bool *error){

    assert(error != NULL);
    switch(type){
        case RL_UNEXPECTED:
            *error = true;
            return true;
            break;
        case RL_DONE:
            
            *error = false;
            return true;
            break;
        default:
            *error = false;
            return false;
        };
        return false;
}
