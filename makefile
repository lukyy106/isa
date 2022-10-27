all: netflow
	#g++ -o flow flow.cpp
	gcc -o netflow netflow.c -lpcap
