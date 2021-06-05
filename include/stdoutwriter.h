#ifndef STDOUTWRITE_H
#define STDOUTWRITE_H
#include <stdint.h>
#include "../include/selector.h"
#include "../include/buffer.h"
#define BUFFER_SIZE 2048

struct writer{
    uint8_t buff[BUFFER_SIZE];
    buffer wb;
    fd_selector selector;
};

void writer_handler(struct selector_key * key);
int writer_initialize(fd_selector selector);
void free_writer();
struct writer * get_writer_data();
#endif