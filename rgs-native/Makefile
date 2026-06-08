CXX ?= g++
CXXFLAGS ?= -std=c++20 -O3 -DNDEBUG -pthread
TARGET ?= rgs
SRC := src/rgs.cpp

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) $(SRC) -o $(TARGET)

self-test: $(TARGET)
	./$(TARGET) --self-test

clean:
	rm -f $(TARGET)
