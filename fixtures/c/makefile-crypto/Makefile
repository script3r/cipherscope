CC=gcc
CFLAGS=-Wall -Wextra -std=c99
LIBS=-lcrypto -lssl
TARGET=basic_crypto
SOURCES=main.c

all: $(TARGET)

$(TARGET): $(SOURCES)
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCES) $(LIBS)

clean:
	rm -f $(TARGET)

.PHONY: all clean