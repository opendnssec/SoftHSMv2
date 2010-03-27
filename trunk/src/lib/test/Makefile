# Temporary Makefile that is used until this project has been auto'd by Rickard ;-)
#
# $Id$

CC=gcc
CFLAGS=-g -Wall `cppunit-config --cflags` -DWITH_OPENSSL -I.. -DSENSITIVE_NON_PAGED

CPP=g++
CPPFLAGS=-g -Wall `cppunit-config --cflags` -DWITH_OPENSSL -I.. -DSENSITIVE_NON_PAGED

LDFLAGS=`cppunit-config --libs` -L..

-include ../Makefile.crypto

CRYPTOSOURCES:=$(patsubst %,../%,$(CRYPTOSOURCES))
CRYPTOHEADERS:=$(patsubst %,../%,$(CRYPTOHEADERS))
CRYPTOOBJECTS:=$(patsubst %,../%,$(CRYPTOOBJECTS))

CRYPTOTESTSOURCES=$(CRYPTOSOURCES) \
cryptotest.cpp \
AESTests.cpp \
ByteStringTests.cpp \
DESTests.cpp \
DSATests.cpp \
HashTests.cpp \
RNGTests.cpp \
RSATests.cpp \
chisq.c \
ent.c \
iso8859.c \
randtest.c
CRYPTOTESTHEADERS=$(CRYPTOHEADERS) \
AESTests.h \
ByteStringTests.h \
DESTests.h \
DSATests.h \
HashTests.h \
RNGTests.h \
RSATests.h \
ent.h \
iso8859.h \
randtest.h
CRYPTOTESTOBJECTS1=$(CRYPTOTESTSOURCES:.cpp=.o)
CRYPTOTESTOBJECTS=$(CRYPTOTESTOBJECTS1:.c=.o)

SOURCES=$(CRYPTOTESTSOURCES)
HEADERS=$(CRYPTOTESTHEADERS)
OBJECTS=$(CRYPTOTESTOBJECTS)

TESTS=cryptotest

all: $(SOURCES) $(HEADERS) $(LIBRARY) $(TESTS)

clean:
	rm -f *.d *.o $(TESTS)

cryptotest: $(CRYPTOTESTSOURCES) $(CRYPTOTESTHEADERS) $(CRYPTOTESTOBJECTS)
	$(CPP) $(LDFLAGS) $(CRYPTOTESTOBJECTS) -o $@

.cpp.o:
	$(CPP) $(CPPFLAGS) $< -c -o $@

.c.o:
	$(CC) $(CFLAGS) $< -c -o $@
