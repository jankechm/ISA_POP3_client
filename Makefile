CC=g++
CFLAGS=-pedantic -Wall -Wextra -std=c++11 -g
FILES = popcl.cpp
	
all: popcl

popcl: $(FILES)
	$(CC) $^ $(CFLAGS) -o $@
