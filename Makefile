PACKAGE = qmail-notify
VERSION = 0.92

CC = gcc
CFLAGS = -O -g -W -Wall

LD = $(CC)
LDFLAGS = -g
LIBS =

install_prefix =
prefix = $(install_prefix)/usr
bindir = $(prefix)/bin

install = /usr/bin/install

SOURCES = qmail-notify.c
PROGS = qmail-notify

all: $(PROGS)

qmail-notify: qmail-notify.o
	$(LD) $(LDFLAGS) -o $@ qmail-notify.o $(LIBS)

install:
	$(install) -d $(bindir)
	$(install) -m 755 $(PROGS) $(SCRIPTS) $(bindir)

clean:
	$(RM) *.o $(PROGS)
