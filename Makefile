CC=g++
CFLAGS=-std=c++11 -Wextra

all:
	$(CC) -g $(CFLAGS) dns.cpp -o dns $(FLAGS) $(LDFLAGS)

.PHONY: clean

clean:
	-rm dns
	-rm test

test:
	-rm test
	$(CC) $(CFLAGS) test.cpp -o test $(FLAGS) $(LDFLAGS)
	./test
