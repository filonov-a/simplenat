#
# (c) aef 2015
#

#
# Path to nfdump codebase
NFDUMPDIR=../nfdump/
NFDUMPBIN=$(NFDUMPDIR)bin

CC=cc
CFLAGS=-Wno-format
NFCFLAGS=-I$(NFDUMPBIN) -I$(NFDUMPDIR) -DHAVE_CONFIG_H -DNSEL
NFLDFLAGS=-L$(NFDUMPBIN) -L/usr/local/lib -lz
NFDUMPOBJS=$(NFDUMPBIN)/nffile.o $(NFDUMPBIN)/flist.o $(NFDUMPBIN)/util.o \
	$(NFDUMPBIN)/minilzo.o 	$(NFDUMPBIN)/nfx.o $(NFDUMPBIN)/exporter.o

TARGETS=nf2nat nat-show nfstat
all: $(TARGETS)

install:
	install $(TARGETS) /usr/local/bin

nf2nat: nf2nat.c
	$(CC) $(NFCFLAGS) -o nf2nat  nf2nat.c  $(NFDUMPOBJS)

nfstat: nfstat.c
	$(CC) $(NFCFLAGS) -o nfstat  nfstat.c  $(NFDUMPOBJS)

nat-show: nat-show.c
	$(CC) -o nat-show $(CFLAGS) nat-show.c

clean:
	rm -f *.o $(TARGETS)

