#ifndef HTTPD_NIO_H
#define HTTPD_NIO_H

#include "../include/selector.h"

void httpd_passive_accept(struct selector_key *key);

#endif
