CC=g++
CFLAGS=-std=c++11 -Wextra

all:
	$(CC) -g $(CFLAGS) dns.cpp -o dns $(FLAGS) $(LDFLAGS)

.PHONY: clean

clean:
	-rm dns
	-rm test

ctest:
	-rm test

test:
	$(CC) -g $(CFLAGS) test.cpp -o test $(FLAGS) $(LDFLAGS)

