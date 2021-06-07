/*
 *  Fuente del script: https://www.mycplus.com/source-code/c-source-code/base64-encode-decode/
 */


#include "../include/buffer.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

 
static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                '4', '5', '6', '7', '8', '9', '+', '/'};
static char *decoding_table = NULL;
static int mod_table[] = {0, 2, 1};
 
 
void base64_cleanup() {
    free(decoding_table);
} 
 
char *base64_encode(const unsigned char *data,
                    size_t input_length,
                    size_t *output_length) {
 
    *output_length = 4 * ((input_length + 2) / 3);
 
    char *encoded_data = malloc(*output_length);
    if (encoded_data == NULL) return NULL;
 
    for (int i = 0, j = 0; i < input_length;) {
 
        uint32_t octet_a = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_b = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_c = i < input_length ? (unsigned char)data[i++] : 0;
 
        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;
 
        encoded_data[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
    }
 
    for (int i = 0; i < mod_table[input_length % 3]; i++)
        encoded_data[*output_length - 1 - i] = '=';

    base64_cleanup();
 
    return encoded_data;
}

char *base64url_encode(const unsigned char *data,
                    size_t input_length,
                    size_t *output_length) {
 
    char * base64_encoded = base64_encode(data, input_length, output_length);

    size_t i = 0;

    for(i = 0; i < *output_length; i++) {
    	switch(base64_encoded[i]) {
    		case '+':
    			base64_encoded[i] = '-';
    			break;

			case '/':
				base64_encoded[i] = '_';
				break;

			case '=':
				base64_encoded[i] = 0;
				break;
    	}
    	if(base64_encoded[i] == 0)
    		break;
    }

    *output_length = i;



 
    return base64_encoded;
}
 
 
/* 

Uso de ejemplo
 
int main(){
    
    char * data = "Hello World!";
    long input_size = strlen(data);
    char * encoded_data = base64_encode(data, input_size, &input_size);
    printf("Encoded Data is: %s \n",encoded_data);
    char * encoded_data = base64url_encode(data, input_size, &input_size);
    printf("Encoded Data is: %s \n",encoded_data);
    
    long decode_size = strlen(encoded_data);
    char * decoded_data = base64_decode(encoded_data, decode_size, &decode_size);
    printf("Decoded Data is: %s \n",decoded_data);
    exit(0);
}

*/