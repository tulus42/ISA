CC=g++
CFLAGS=-std=c++11 -Wextra

all:
	$(CC) $(CFLAGS) dns.cpp -o dns $(FLAGS) $(LDFLAGS)

.PHONY: clean

clean:
	-rm dns