# Makefile for llmnrd
#
# Copyright (C) 2014-2015 Tobias Klauser <tklauser@distanz.ch>

P 	= llmnrd
OBJS	= llmnr.o iface.o socket.o util.o main.o
LIBS	= -lpthread

CC	= $(CROSS_COMPILE)gcc

CFLAGS	?= -W -Wall -O2
LDFLAGS	?=

CCQ	= @echo -e "  CC\t$<" && $(CC)
LDQ	= @echo -e "  LD\t$@" && $(CC)

all: $(P)

$(P): $(OBJS)
	$(LDQ) $(LDFLAGS) -o $@ $(OBJS) $(LIBS)

%.o: %.c %.h
	$(CCQ) $(CFLAGS) -o $@ -c $<

%.o: %.c
	$(CCQ) $(CFLAGS) -o $@ -c $<

clean:
	@echo -e "  CLEAN"
	@rm -f $(OBJS) $(P)
