# Makefile for llmnrd
#
# Copyright (C) 2014-2017 Tobias Klauser <tklauser@distanz.ch>

VERSION = 0.4

# llmnrd binary
D_P 	= llmnrd
D_OBJS	= llmnr.o iface.o socket.o util.o llmnrd.o
D_LIBS	=
D_MAN	= $(D_P).8

# llmnr-query binary
Q_P 	= llmnr-query
Q_OBJS	= util.o llmnr-query.o
Q_LIBS	=
Q_MAN	= $(Q_P).1

CC	= $(CROSS_COMPILE)gcc
INSTALL	= install
GZIP	= gzip -9 -c

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

CFLAGS_WARN := -Wextra 			\
	-Waggregate-return		\
	-Wbad-function-cast		\
	-Wdeclaration-after-statement	\
	-Wformat-nonliteral		\
	-Wformat-security		\
	-Wmissing-declarations		\
	-Wmissing-format-attribute	\
	-Wmissing-prototypes		\
	-Wsign-compare			\
	-Wstrict-prototypes		\
	-Wundef				\
	-Wunused			\
	-Wwrite-strings

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
MAN1DIR = $(prefix)/share/man/man1
MAN8DIR = $(prefix)/share/man/man8
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
	$(Q)$(GZIP) doc/$(D_MAN) > $(D_MAN).gz
	$(Q)$(INSTALL) -d -m 755 $(DESTDIR)$(MAN8DIR)
	$(Q)$(INSTALL) -m 644 $(D_MAN).gz $(DESTDIR)$(MAN8DIR)/$(D_MAN).gz

install_$(Q_P): $(Q_P)
	@echo "  INSTALL $(Q_P)"
	$(Q)$(INSTALL) -d -m 755 $(DESTDIR)$(BINDIR)
	$(Q)$(INSTALL) -m 755 $(Q_P) $(DESTDIR)$(BINDIR)/$(Q_P)
	$(Q)$(GZIP) doc/$(Q_MAN) > $(Q_MAN).gz
	$(Q)$(INSTALL) -d -m 755 $(DESTDIR)$(MAN1DIR)
	$(Q)$(INSTALL) -m 644 $(Q_MAN).gz $(DESTDIR)$(MAN1DIR)/$(Q_MAN).gz

install: install_$(D_P) install_$(Q_P)

clean:
	@echo "  CLEAN"
	$(Q)rm -f $(D_OBJS) $(D_P)
	$(Q)rm -f $(Q_OBJS) $(Q_P)
	$(Q)rm -f $(D_P).8.gz
	$(Q)rm -f $(Q_P).1.gz

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
