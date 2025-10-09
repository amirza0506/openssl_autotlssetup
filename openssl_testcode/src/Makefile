CC = gcc
CFLAGS = -O2 -Wall -fPIC `pkg-config --cflags liboqs 2>/dev/null || true` -I/usr/include
LDLIBS = -lssl -lcrypto
PKG_OQS = $(shell pkg-config --libs liboqs 2>/dev/null || echo "")

# if liboqs present, define HAVE_LIBOQS
CFLAGS += $(shell pkg-config --exists liboqs && echo -DHAVE_LIBOQS)

SRC = src/crypto_api.c src/demo_cli.c
OBJS = $(patsubst src/%.c,build/%.o,$(wildcard src/*.c))
TARGET_LIB = lib/libcryptoapi.so
DEMO = bin/demo_cli

.PHONY: all clean

all: $(TARGET_LIB) $(DEMO)

build/%.o: src/%.c | build
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET_LIB): build/crypto_api.o | lib
	$(CC) -shared -o $@ $^ $(PKG_OQS) $(LDLIBS)

$(DEMO): build/demo_cli.o $(TARGET_LIB) | bin
	$(CC) -o $@ $^ -Llib -lcryptoapi $(PKG_OQS) $(LDLIBS) -Wl,-rpath,'$$ORIGIN/../lib'

build:
	mkdir -p build

lib:
	mkdir -p lib

bin:
	mkdir -p bin

clean:
	rm -rf build lib bin
