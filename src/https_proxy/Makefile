src = $(wildcard *.c)
obj = $(src:.c=.o)
CC = gcc
CFLAGS = -Wall -Wextra -g
LDFLAGS = -lssl -lcrypto -lpthread -lcurl

proxy: $(obj)
	$(CC) -o $@ $^ $(LDFLAGS)

.PHONY: clean
clean:
	rm -f $(obj) a.out
