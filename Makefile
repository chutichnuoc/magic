  
# Compiler: gcc for C/C++ program
CC = g++

# Compiler flags:
# -g: adds debugging info to .exe file
# -Wall: turns on most compiler warnings
CFLAGS = -Wall -pthread -lstdc++
LIBS = -lpcap -lm -lnetfilter_queue

SRC := src/cpp
OBJ := obj
TARGET := target/magic

SOURCES := $(wildcard $(SRC)/*.cpp)
OBJECTS := $(patsubst $(SRC)/%.cpp, $(OBJ)/%.o, $(SOURCES))

all: $(OBJECTS)
	$(CC) $(CFLAGS) -o $(TARGET) $^ $(LIBS)

$(OBJ)/%.o: $(SRC)/%.cpp
	$(CC) $(CFLAGS) -I$(SRC) -c $< -o $@ $(LIBS)

clean:
	$(RM) $(OBJ)/*.o $(shell find . -type f -executable ! -name "*.*")