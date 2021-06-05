#include "../include/stdoutwriter.h"
#include "../include/buffer.h"
#include "../include/selector.h"
#include <stdlib.h>
#define N(x) (sizeof(x)/sizeof((x)[0]))

struct stdout_writer main_writer;

struct stdout_writer * get_writer_data(){
    return &main_writer;
}

int stdout_writer_initialize(fd_selector* selector){
	main_writer->selector = selector;
	buffer_init(&main_writer->wb, N(main_writer->write_buffer_data), main_writer->write_buffer_data);
	return 1;
}

void stdout_write(struct selector_key * key){

	struct stdout_writer *writer = (struct stdout_writer *)key->data;
	buffer *wb = &writer->wb;
	size_t rBytes;
	uint8_t *write_ptr = buffer_can_read(wb,&rBytes);
	ssize_t numBytesWritten = writer(1, write_ptr, rBytes);
	if(numBytesWritten > 0){
		if(numBytesWritten < rBytes){
			buffer_read_adv(wb,numBytesWritten);
		}
		else{
			buffer_read_adv(wb,rBytes);
			selector_set_interest_key(key, OP_NOOP);
		}
	}
}


