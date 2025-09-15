CXX=g++
CXXFLAGS=-Wall -Wextra -std=c++17
LIBS=-lbotan-2
TARGET=botan_test
SOURCES=main.cpp

all: $(TARGET)

$(TARGET): $(SOURCES)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SOURCES) $(LIBS)

clean:
	rm -f $(TARGET)

.PHONY: all clean