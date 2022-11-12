CFLAGS:=-std=c99 -Wall -Wextra -pedantic -Wno-unused-variable -D_BSD_SOURCE
LFLAGS:=-lpcap
netflow: netflow.o
	gcc $(CFLAGS) -o netflow netflow.o $(LFLAGS)
netflow.o: netflow.c netflow.h
	gcc $(CFLAGS) -c netflow.c netflow.h
