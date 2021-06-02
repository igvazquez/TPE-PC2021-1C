#ifndef NIO_STDOUT_H
#define NIO_STDOUT_H

#include "../include/buffer.h"

#define MAX_STDOUT_BUFFER_LENGTH 8*1024

struct nio_stdout{
    uint8_t stdout_buffer_data[MAX_STDOUT_BUFFER_LENGTH];
    buffer stdout_buffer;
};


#endif

