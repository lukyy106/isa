CINCLUDES = -I../deps/libpcap/ -I../deps/lua/src
CLIBS = ../deps/libpcap/libpcap.a ../deps/lua/src/liblua.a
LOAD_LIBS=-lm -ldl -lpthread

all: netflow
	gcc netflow.c netflow -lpcap -o $(CINCLUDES) $(CLIBS) $(LOAD_LIBS)
