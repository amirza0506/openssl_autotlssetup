CC=gcc
CFLAGS=-Wall -O2 -I./src/include
LIBS=-lssl -lcrypto -lpthread

SRC=src

all:
	$(CC) $(CFLAGS) $(SRC)/server.c $(SRC)/tun.c $(SRC)/utils.c -o server $(LIBS)
	$(CC) $(CFLAGS) $(SRC)/client.c $(SRC)/tun.c $(SRC)/utils.c -o client $(LIBS)

clean:
	rm -f server client
