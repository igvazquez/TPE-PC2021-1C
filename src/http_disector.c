#include "../include/http_disector.h"
#include "../include/request_line.h"
#include "../include/parser.h"
#include "../include/mime_chars.h"
#include "../include/register_log.h"
#include "../include/request_message.h"
#include "../include/base64.h"
#include <string.h>
#include <stdbool.h>
#include <assert.h>
#include <stdio.h>

void http_disector_reset(struct http_disector *disector);

void decode_credentials(struct request_message_parser * parser,struct  log_data*log_data){
    assert(parser != NULL && parser->current_detection != NULL);
    char *value = get_detection_value(parser);
    char *auth_type = strtok(value, " ");

  
    // Podria extenderse a desencodear otros tipos de Authorization
    if(strcmp(auth_type,"Basic") == 0){
          char *encode = strtok(NULL," ");
          size_t encode_len = strlen(encode);
          char decode[encode_len+1];
          Base64decode(decode, encode); 
          log_data->user = strtok(decode,":");
          log_data->password = strtok(NULL,":");
          log_data->protocol = HTTP;
          register_password(log_data);
    }   
}

void http_disector_init(struct http_disector *disector,struct log_data* log_data){
    assert(disector != NULL);
    disector->rl_parser = parser_init(init_char_class(), request_line_parser_definition());
    disector->log_data = log_data;
    request_message_parser_init(&disector->rm_parser,1,false);
    add_header(&disector->rm_parser,"Authorization",HEADER_STORAGE,NULL,decode_credentials);
    http_disector_reset(disector);
}

void http_disector_reset(struct http_disector* disector){
    parser_reset(disector->rl_parser);
    request_message_parser_reset(&disector->rm_parser);
    disector->state = HTTP_REQUEST_LINE;
}

void http_disector_feed(struct http_disector *disector, uint8_t c){

   const  struct parser_event *e;
   bool error = false;
   bool done = false;
  
   switch (disector->state)
   {
   case HTTP_REQUEST_LINE:

       e = parser_feed(disector->rl_parser, c);
       if (e->type == RL_DONE)
       {
         
           disector->state = HTTP_HEADERS;
       }
       else if (e->type == RL_UNEXPECTED)
       {
           
           parser_reset(disector->rl_parser);
           disector->state = HTTP_REQUEST_LINE;
       }
       break;
   case HTTP_HEADERS:
 
       e = parser_feed(disector->rm_parser.rm_parser, c);
       done = request_message_parser_process(e, &disector->rm_parser, &error,disector->log_data);
       if(done|| error){
           http_disector_reset(disector);
       }
       break;
   }

}
void http_disector_consume(struct http_disector *disector, buffer *b){
    size_t nBytes;
    uint8_t* readPtr = buffer_read_ptr(b,&nBytes);
    uint8_t c;
    for (unsigned i = 0; i < nBytes;i++){
        http_disector_feed(disector,readPtr[i]);
    }

    return;
}
