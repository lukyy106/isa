CFLAGS:=-std=c99 -Wall -Wextra -pedantic -Wno-unused-variable
LFLAGS:=-lpcap
netflow: netflow.o
	gcc $(CFLAGS) netflow netflow.o $(LFLAGS)
netflow.o: netflow.c
	gcc $(CFLAGS) -c netflow.c netflow.o
