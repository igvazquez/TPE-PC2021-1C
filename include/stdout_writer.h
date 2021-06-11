#ifndef STDOUTWRITE_H
#define STDOUTWRITE_H
#include <stdint.h>
#include "../include/selector.h"
#include "../include/buffer.h"
#define  STDOUT_BUFFER_SIZE 25500 // 510 clientes * 50 caracteres

#define  STDOUT_FILENO 1

struct stdout_writer{
    uint8_t write_buffer_data[STDOUT_BUFFER_SIZE];
    buffer wb;
    fd_selector selector;
};

void stdout_write(struct selector_key * key);
void stdout_writer_initialize(fd_selector selector);
struct stdout_writer * get_stdout_writer_data();
#endif