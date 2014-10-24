all: randstprober

INCLUDES=util.h proberoute.h tracer.h socket.h
ARTSCLASSLIB = 
ARTSCLASSINC = 
LIBTOOL = @ /bin/sh ../artsclasses/libtool

CPPFLAGS=-g $(ARTSCLASSINC) -Ilinux-include
.cc.o: $(INCLUDES)
		g++ $(CPPFLAGS) -c $<

CFLAGS=-DHAVE_MALLOC_H=1 -DHAVE_SYS_SELECT_H=1 -DHAVE_NET_ROUTE_H=1 -DHAVE_STRERROR=1 -DHAVE_USLEEP=1 -DHAVE_SETLINEBUF=1 -DBYTESWAP_IP_HDR=1 -DHAVE_ICMP_NEXTMTU=1  -I.  -Ilinux-include -g -Wall
.c.o: $(INCLUDES)
		gcc $(CFLAGS) -c $<

randstprober: randstprober.cc destlist.o simpledestlist.o tracer.o findsaddr-linux.o ifaddrlist.o util.o socket.o hashtable.o asmapper.o radix.o buffer.o $(INCLUDES)
		g++ -o randstprober $(CPPFLAGS) randstprober.cc destlist.o simpledestlist.o tracer.o findsaddr-linux.o ifaddrlist.o util.o socket.o hashtable.o asmapper.o radix.o buffer.o -g $(ARTSCLASSLIB) -lpthread -lpcap

clean:
		rm -f randstprober *.o
