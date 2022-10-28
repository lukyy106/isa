all: netflow
	gcc netflow.c netflow -lpcap -o
