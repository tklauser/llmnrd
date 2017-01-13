# Makefile for llmnrd
#
# Copyright (C) 2014-2017 Tobias Klauser <tklauser@distanz.ch>

VERSION = 0.2.1

# llmnrd binary
D_P 	= llmnrd
D_OBJS	= llmnr.o iface.o socket.o util.o llmnrd.o
D_LIBS	=

# llmnr-query binary
Q_P 	= llmnr-query
Q_OBJS	= util.o llmnr-query.o
Q_LIBS	=

CC	= $(CROSS_COMPILE)gcc
INSTALL	= install

CPPFLAGS ?=
LDFLAGS	?=

ifeq ($(shell git rev-parse > /dev/null 2>&1; echo $$?), 0)
  GIT_VERSION = "(git id $(shell git describe --always))"
else
  GIT_VERSION =
endif

CFLAGS_MIN := -W -Wall -DVERSION_STRING=\"v$(VERSION)\" -DGIT_VERSION=\"$(GIT_VERSION)\"
ifeq ($(DEBUG), 1)
  CFLAGS_MIN += -g -DDEBUG
endif

CFLAGS_WARN := -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations	\
	-Wdeclaration-after-statement -Wsign-compare -Winit-self		\
	-Wformat-nonliteral -Wformat-security -Wmissing-format-attribute	\
	-Wundef -Wbad-function-cast -Waggregate-return -Wunused -Wwrite-strings

CFLAGS ?= -O2 $(CFLAGS_WARN)
override CFLAGS := $(CFLAGS_MIN) $(CFLAGS)

Q	?= @
ifeq ($(Q),)
  CCQ	= $(CC)
  LDQ	= $(CC)
else
  CCQ	= $(Q)echo "  CC $<" && $(CC)
  LDQ	= $(Q)echo "  LD $@" && $(CC)
endif

prefix	?= /usr/local

BINDIR	= $(prefix)/bin
SBINDIR	= $(prefix)/sbin
DESTDIR	=

all: $(D_P) $(Q_P)

$(D_P): $(D_OBJS)
	$(LDQ) $(LDFLAGS) -o $@ $(D_OBJS) $(D_LIBS)

$(Q_P): $(Q_OBJS)
	$(LDQ) $(LDFLAGS) -o $@ $(Q_OBJS) $(Q_LIBS)

%.o: %.c %.h
	$(CCQ) $(CFLAGS) $(CPPFLAGS) -o $@ -c $<

%.o: %.c
	$(CCQ) $(CFLAGS) $(CPPFLAGS) -o $@ -c $<

install_$(D_P): $(D_P)
	@echo "  INSTALL $(D_P)"
	$(Q)$(INSTALL) -d -m 755 $(DESTDIR)$(SBINDIR)
	$(Q)$(INSTALL) -m 755 $(D_P) $(DESTDIR)$(SBINDIR)/$(D_P)

install_$(Q_P): $(Q_P)
	@echo "  INSTALL $(Q_P)"
	$(Q)$(INSTALL) -d -m 755 $(DESTDIR)$(BINDIR)
	$(Q)$(INSTALL) -m 755 $(Q_P) $(DESTDIR)$(BINDIR)/$(Q_P)

install: install_$(D_P) install_$(Q_P)

clean:
	@echo "  CLEAN"
	$(Q)rm -f $(D_OBJS) $(D_P)
	$(Q)rm -f $(Q_OBJS) $(Q_P)

# Maintainer targets

GIT_TAG = git tag -a v$(VERSION) -s -m "llmnrd $(VERSION) release"
GIT_ARCHIVE = git archive --prefix=llmnrd-$(VERSION)/ v$(VERSION) | \
	      $(1) -9 > ../llmnrd-$(VERSION).tar.$(2)
GPG_SIGN = gpg -a --output ../llmnrd-$(VERSION).tar.$(1).asc --detach-sig \
		../llmnrd-$(VERSION).tar.$(1)
release:
	$(GIT_TAG)
	$(call GIT_ARCHIVE,gzip,gz)
	$(call GIT_ARCHIVE,bzip2,bz2)
	$(call GPG_SIGN,gz)
	$(call GPG_SIGN,bz2)
	$(Q)echo "Created release $(VERSION)"
