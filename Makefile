CC      = gcc -g
CFLAGS  = -O2 -Wall -Wextra -Ithird_party/uthash
LDFLAGS =
LDLIBS  = -lssl -lcrypto   #  TLS

# Try to auto-detect Homebrew OpenSSL include/lib paths on macOS
OPENSSL_PREFIX := $(shell brew --prefix openssl@3 2>/dev/null || brew --prefix openssl 2>/dev/null || echo)
ifneq ($(OPENSSL_PREFIX),)
CFLAGS += -I$(OPENSSL_PREFIX)/include
LDFLAGS += -L$(OPENSSL_PREFIX)/lib
endif

SRCS    = $(wildcard *.c)
OBJS    = $(SRCS:.c=.o)
TARGET  = proxy

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -o $@ $(OBJS) $(LDFLAGS) $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)
