#include "../include/stdoutwriter.h"
#define N(x) (sizeof(x)/sizeof((x)[0]))

struct writer *writer_data = NULL;

struct writer * get_writer_data(){
    return writer_data;
}

int writer_initialize(fd_selector selector){
	writer_data = malloc(sizeof(*writer_data));
	if(writer_data == NULL){
		return -1;
	}
	writer_data->selector = selector;
	buffer_init(&writer_data->wb, N(writer_data->raw_buff), writer_data->raw_buff);
	return 1;
}

void writer_handler(struct selector_key * key){
	struct writer *write = (struct writer *)key->data;
	buffer *b = &writer->wb;
	size_t size;
	ssize_t n = writer(1, ptr, size);
	if(n > 0){
		if((unsigned)n < size){
			buffer_read_adv(b,n);
		}
		else{
			buffer_read_adv(b,size);
			selector_set_interest_key(key, OP_NOOP);
		}
	}
}

void free_writer(){
    if(writer_data != NULL){
        free(writer_data);
    }
}
