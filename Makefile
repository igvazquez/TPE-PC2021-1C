HEADERS=include
SRC=src

HFILES=$(shell find $(HEADERS) -name '*.h' | sed 's/^.\///')

FILES=$(shell find $(SRC) -name '*.c' | sed 's/^.\///')
OFILES=$(patsubst %.c,./%.o,$(FILES))

CFLAGS = -Wall -g -Wextra -pedantic -pedantic-errors -O3 -pthread -std=c11 -D_POSIX_C_SOURCE=200112L $(MYCFLAGS)

DEBUG_FLAGS = -Wall -Wextra -pedantic -pedantic-errors \
	-fsanitize=address -g -std=c11 -D_POSIX_C_SOURCE=200112L $(MYCFLAGS)

%.o: %.c $(HFILES)
	$(CC) -c -o $@ $< $(CFLAGS)

all: httpd

httpd: $(OFILES)
	$(CC) $(OFILES) $(CFLAGS) -o  httpd



.PHONY: clean

clean: 
	rm -rf $(OFILES)