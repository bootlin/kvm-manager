DESTDIR=
BINDIR=/usr/bin
MANDIR=/usr/share/man
QEMUSTARTGROUP=kvm

PACKAGE=qemu-start
VERSION=2.0
FILES=AUTHORS COPYING NEWS README Makefile qemu-start.c qemu-start.1 qemu-start.ggo
BASENAME=$(PACKAGE)-$(VERSION)

CFLAGS=-Wall -W

all: qemu-start

qemu-start : qemu-start.o cmdline.o qemu-start.c cmdline.c cmdline.h qemu-start.ggo
	$(CC) -o qemu-start qemu-start.o cmdline.o

cmdline.o : cmdline.c cmdline.h qemu-start.ggo

qemu-start.o: qemu-start.c cmdline.h qemu-start.ggo

cmdline.c : qemu-start.ggo
	gengetopt -i qemu-start.ggo -u

# Automake FAQ: make cmdline.h depend on cmdline.c to compensate for parallel
# make problems (gengetopt produces two result files).
cmdline.h : cmdline.c qemu-start.ggo
	gengetopt -i qemu-start.ggo -u

install:
	install -d $(DESTDIR)$(BINDIR)
	install -o root -g $(QEMUSTARTGROUP) -m 4710 qemu-start $(DESTDIR)$(BINDIR)
	install -d $(DESTDIR)$(MANDIR)/man1
	install -o root -g root -m 755 qemu-start.1 $(DESTDIR)$(MANDIR)/man1

clean:
	$(RM) qemu-start
	$(RM) cmdline.o
	$(RM) qemu-start.o
	$(RM) cmdline.c
	$(RM) cmdline.h

package:
	ln -s . $(BASENAME)
	tar cfvzp $(BASENAME).tar.gz $(addprefix $(BASENAME)/,$(FILES))
	$(RM) $(BASENAME)
