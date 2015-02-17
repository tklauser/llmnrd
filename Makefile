# Makefile for llmnrd
#
# Copyright (C) 2014-2015 Tobias Klauser <tklauser@distanz.ch>

P 	= llmnrd
OBJS	= llmnr.o iface.o socket.o util.o main.o
LIBS	= -lpthread

CC	= $(CROSS_COMPILE)gcc
INSTALL	= install

CFLAGS	?= -W -Wall -O2
LDFLAGS	?=

ifeq ($(DEBUG), 1)
  CFLAGS += -g -DDEBUG
endif

CCQ	= @echo "  CC $<" && $(CC)
LDQ	= @echo "  LD $@" && $(CC)

prefix	?= /usr/local

BINDIR	= $(prefix)/bin
DESTDIR	=

all: $(P)

$(P): $(OBJS)
	$(LDQ) $(LDFLAGS) -o $@ $(OBJS) $(LIBS)

install_$(P): $(P)
	@echo "  INSTALL $(P)"
	@$(INSTALL) -d -m 755 $(DESTDIR)$(BINDIR)
	@$(INSTALL) -m 755 $(P) $(BINDIR)/$(P)

%.o: %.c %.h
	$(CCQ) $(CFLAGS) -o $@ -c $<

%.o: %.c
	$(CCQ) $(CFLAGS) -o $@ -c $<

install: install_$(P)

clean:
	@echo "  CLEAN"
	@rm -f $(OBJS) $(P)
