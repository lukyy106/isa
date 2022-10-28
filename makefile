all: netflow
	gcc netflow.c -o netflow -lpcap bin
