#include "../include/dns.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


/*
<33 bytes represented by the following hex encoding>


|-------------HEADER --------------|                     
|                                  |
00 00 01 00 00 01 00 00 00 00 00 00 03 77 77 77
07 65 78 61 6d 70 6c 65 03 63 6f 6d 00 00 01 00
01
In this example, the 33 bytes are the DNS message in DNS wire format
[RFC1035], starting with the DNS header.
*/

//El header tiene 96 bits = 12 bytes

#define HEADER_BYTES 12
#define AAAA_QTYPE 0x0c
#define A_QTYPE 0x01

void create_header(unsigned  char * result){

    unsigned char aux [] = {0x00,0x00,0x01,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00};
    memcpy(result,aux,HEADER_BYTES);

}


void invertir(unsigned char * response, int len) {
    for(int i = 0; i < len; i+=2) {
        if(i+1 < len) {
            char aux = response[i+1];
            response[i+1] = response[i];
            response[i] = aux;
        }
    }
}



/*
    Para agarrar un sockadrin del storage hay q agarrar algun elemenos del array de storage, y castearlo al sockadrin correspondiente
 */

void parse_header(dns_response * parsed_response, unsigned char * response) {

    parsed_response->header.id = ntohs(*((short *) response));
    parsed_response->header.query_or_response = response[2] >> 7;
    parsed_response->header.opcode = (response[2] & 0x78) >> 3;
    parsed_response->header.authoritative_answer = (response[2] & 0x4) >> 2;
    parsed_response->header.truncated_message = (response[2] & 0x2) >> 1;
    parsed_response->header.recursion_desired = response[2] & 0x1;

    parsed_response->header.recursion_available = (response[3] & 0x80) >> 7;
    parsed_response->header.z_reserved = (response[3] & 0x40) >> 6;
    parsed_response->header.authenticated_data = (response[3] & 0x20) >> 5;
    parsed_response->header.checking_disabled = (response[3] & 0x10) >> 4;
    parsed_response->header.response_code = response[3] & 0xf;

    parsed_response->header.q_count = ntohs(*((short *) (response + 4)));
    parsed_response->header.ans_count = ntohs(*((short *) (response + 6)));
    parsed_response->header.auth_count = ntohs(*((short *) (response + 8)));
    parsed_response->header.add_count = ntohs(*((short *) (response + 10)));

}


dns_response * parse_answer(unsigned char * response, size_t bytes, struct sockaddr_storage  * storage, int * qty) {
    dns_response *parsed_response = malloc(sizeof(dns_response));



    if (parsed_response != NULL) {

        parse_header(parsed_response,response);


        int idx = 12;
        while (response[idx] != 0x00) idx++;
        idx += 5; //Consumimos el 0x00 de fin de qname y 4 de qtype y qclass
        response += idx;
       // memset(resolve_info->storage, 0, sizeof(resolve_info->storage));

        for (int rta_num = 0; rta_num < parsed_response->header.ans_count; rta_num++) {
            //Consumo hasta encontrar un 0x00 al igual que antes
            idx = 0;
            while (!((response[idx] == 0xc0) && response[idx + 1] == 0x0c) && response[idx] != 0x00) idx++;
            if (response[idx] == 0x00)
                idx++; //Consumo el 0x00
            else
                idx += 2; //Consumo el 0xc0 0x0c
            unsigned short qtype = ntohs(*((short *) (response + idx)));
            idx += 4; //Consumo 2 bytes del qtype y 2 mas innecesarios

            uint32_t ttl=0;
            memcpy(&ttl,response + idx, sizeof(ttl));


            ttl = ntohl(ttl);
            idx += 4; //Consumo 4 bytes del ttl
            unsigned short data_length = ntohs(*((short *) (response + idx)));
            idx += 2; // Consumo 2 bytes del data_length

            /*char * puntero_a_ip;*/
            //struct sockaddr_storage storage;

            if (qtype == A_QTYPE) {
               // storage.ss_family = AF_INET;
                struct sockaddr_in ipv4;
                memset(&ipv4, 0, sizeof(struct sockaddr_in));
                ipv4.sin_family = AF_INET;
                uint32_t  aux = 0;
                memcpy(&aux,response + idx, sizeof(uint32_t));

                ipv4.sin_addr.s_addr = aux;
                memcpy(&storage[rta_num], (struct  sockaddr_storage *) &ipv4,sizeof(ipv4));



            } else {
                struct sockaddr_in6 ipv6;
                memset(&ipv6,0,sizeof(struct sockaddr_in6));
                ipv6.sin6_family = AF_INET6;

                memcpy(ipv6.sin6_addr.__in6_u.__u6_addr8, response + idx, data_length);
                memcpy(&storage[rta_num], (struct  sockaddr_storage *) &ipv6,sizeof(ipv6));

            }
            (*qty)++;
            response += idx;

        }

        return parsed_response;
    }
}

int create_question(char * fqdn, unsigned char * result, char qtype){

    /*Qname :  a domain name represented as a sequence of labels, where
                each label consists of a length octet followed by that
                number of octets.  The domain name terminates with the
                zero length octet for the null label of the root.  Note
                that this field may be an odd number of octets; no
                padding is used. */


    int i = 0, j=0; //i itera el fqdn, j sirve para poner el byte q indica la cantidad de octetos

    int fqdn_len = strlen(fqdn);
    while (i< fqdn_len){
        //Tenemos que armar labels, arrancando con la cantidad de octetos, y luego esos octetos
        if (fqdn[i] != '.'){

            //guardamos un lugar para el byte de la cantidad
            result[i+1] = fqdn[i];

        }else{
            //terminamos de armar el label, poniendo la cant de octetos en el lugar reservado
            result[j] = 3;//i-j;
            j= i+1;

        }
        i++;
    }
    if(fqdn[i-1] != '.')
        result[j] = i-j;
    else
        i--;
    result[++i] = 0;

    //Colocamos el QTYPE y QCLASS
    result[++i] = 0x00;
    result[++i] = qtype;
    result[++i] = 0x00;
    result[++i] = 0x01; 
    return i+1;
}

void generate_query(char * fqdn, unsigned char * result, int * dns_query_size, enum ip_type ip_type){

    create_header(result);

    //Despues del header viene la question zone, formada por QNAME - QTYPE - QCLASS


    int len = create_question(fqdn,result +  HEADER_BYTES, ip_type == IPV4 ?  A_QTYPE : AAAA_QTYPE);

    *dns_query_size = len + HEADER_BYTES;

}


/*

int main() {

  /*  unsigned char response[] = {  0x00, 0x00, 0x80, 0x81, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x77, 0x03, 0x77, 0x77,
                        0x67, 0x06, 0x6f, 0x6f, 0x6c, 0x67, 0x03, 0x65, 0x6f, 0x63, 0x00, 0x6d, 0x01, 0x00, 0x01, 0x00,
                        0x0c, 0xc0, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x22, 0x00, 0x04, 0x00, 0x3a, 0xd8, 0x24, 0xde};


    invertir(response, 48); // Asi vendría la rta


    */
    /*unsigned char response[] = {
            0x01, 0xc7, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x01, 0x06, 0x67, 0x6f, 0x6f,
            0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
            0x00, 0x1c, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x1c,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x67, 0x00, 0x10,
            0x28, 0x00, 0x03, 0xf0, 0x40, 0x02, 0x08, 0x0a,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x0e,
            0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00 };

            */

/*
    unsigned char response[] = {
            0x70, 0x0d, 0x81, 0x80, 0x00, 0x01, 0x00, 0x03,
            0x00, 0x00, 0x00, 0x01, 0x06, 0x61, 0x6d, 0x61,
            0x7a, 0x6f, 0x6e, 0x03, 0x63, 0x6f, 0x6d, 0x00,
            0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x04,
            0xcd, 0xfb, 0xf2, 0x67, 0xc0, 0x0c, 0x00, 0x01,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x04,
            0x36, 0xef, 0x1c, 0x55, 0xc0, 0x0c, 0x00, 0x01,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x04,
            0xb0, 0x20, 0x67, 0xcd, 0x00, 0x00, 0x29, 0x02,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

            */





    //    parse_answer(response, 87, storage);


    //dns_response * parsed_response = parse_answer(response, 48);

    /*for(int i = 0; i < 48; i++)
        putchar(response[i]);*/
    /*char * buff = malloc(500);
    size_t size = 0;
    int sizee = 0;
    generate_query("www.google.com", buff, &sizee);
    for(int i = 0; i < sizee; i++)
        putchar(buff[i]);*/
    //printf("%s\n", base64url_encode(buff, size, &size));


  //  return 0;
//}




