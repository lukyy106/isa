all: netflow
	#g++ -o flow flow.cpp
	gcc netflow.c -o netflow -lpcap -L/usr/local//include/pcap/pcap.h
