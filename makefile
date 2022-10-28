all: netflow
	#g++ -o flow flow.cpp
	gcc netflow.c -o netflow -lpcap
