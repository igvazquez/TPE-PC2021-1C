#include "../include/stdout_writer.h"
#include "../include/buffer.h"
#include "../include/selector.h"
#include <stdlib.h>
#define N(x) (sizeof(x)/sizeof((x)[0]))



struct stdout_writer main_writer;

struct stdout_writer * get_stdout_writer_data(){
    return &main_writer;
}

void stdout_writer_initialize(fd_selector selector){
	main_writer.selector = selector;
	buffer_init(&main_writer.wb, N(main_writer.write_buffer_data), main_writer.write_buffer_data);
}

void stdout_write(struct selector_key * key){

	struct stdout_writer *writer = (struct stdout_writer *)key->data;
	buffer *wb = &writer->wb;
	size_t rBytes;
	uint8_t *write_ptr = buffer_read_ptr(wb,&rBytes);
	ssize_t numBytesWritten = write(STDOUT_FILENO, write_ptr, rBytes);
	if(numBytesWritten > 0){
		if((unsigned)numBytesWritten < rBytes){
			buffer_read_adv(wb,numBytesWritten);
		}
		else{
			buffer_read_adv(wb,rBytes);
			if(SELECTOR_SUCCESS != selector_set_interest_key(key, OP_NOOP)){
				abort();
			}
		}
	}
}


