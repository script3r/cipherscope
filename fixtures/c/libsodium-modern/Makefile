CC=gcc
CFLAGS=-Wall -Wextra -std=c99
LIBS=-lsodium
TARGET=sodium_test
SOURCES=main.c

all: $(TARGET)

$(TARGET): $(SOURCES)
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCES) $(LIBS)

clean:
	rm -f $(TARGET)

.PHONY: all clean