CC=gcc
CFLAGS=-Wall -Wextra -std=c99
LIBS=-lssl -lcrypto -lsodium
TARGET=crypto_test
SOURCES=main.c

all: $(TARGET)

$(TARGET): $(SOURCES)
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCES) $(LIBS)

clean:
	rm -f $(TARGET)

install: $(TARGET)
	cp $(TARGET) /usr/local/bin/

.PHONY: all clean install