# Temporary Makefile that is used until this project has been auto'd by Rickard ;-)
#
# $Id$

CC=gcc
CFLAGS=-g -Wall `cppunit-config --cflags` -DWITH_OPENSSL

CPP=g++
CPPFLAGS=-g -Wall `cppunit-config --cflags` -DWITH_OPENSSL

LDFLAGS=-lcrypto

TESTLDFLAGS=$(LDFLAGS) `cppunit-config --libs`

CRYPTOSOURCES=\
BotanCryptoFactory.cpp \
ByteString.cpp \
CryptoFactory.cpp \
OSSLCryptoFactory.cpp \
SecureMemoryRegistry.cpp \
log.cpp
CRYPTOHEADERS=\
AsymmetricAlgorithm.h \
AsymmetricKeyPair.h \
BotanCryptoFactory.h \
ByteString.h \
CryptoFactory.h \
HashAlgorithm.h \
OSSLCryptoFactory.h \
PrivateKey.h \
PublicKey.h \
RNG.h \
SecureAllocator.h \
SecureMemoryRegistry.h \
Serialisable.h \
SymmetricAlgorithm.h \
SymmetricKey.h \
log.h
CRYPTOOBJECTS1=$(CRYPTOSOURCES:.cpp=.o)
CRYPTOOBJECTS=$(CRYPTOOBJECTS1:.c=.o)

CRYPTOTESTSOURCES=$(CRYPTOSOURCES) \
cryptotest.cpp
CRYPTOTESTHEADERS=$(CRYPTOHEADERS)
CRYPTOTESTOBJECTS1=$(CRYPTOTESTSOURCES:.cpp=.o)
CRYPTOTESTOBJECTS=$(CRYPTOTESTOBJECTS1:.c=.o)

LIBSOURCES=
LIBHEADERS=
LIBOBJECTS1=$(LIBSOURCES:.cpp=.o)
LIBOBJECTS=$(LIBOBJECTS1:.c=.o)

SOURCES=$(CRYPTOSOURCES) $(LIBSOURCES)
HEADERS=$(CRYPTOHEADERS) $(LIBHEADERS)
OBJECTS=$(CRYPTOOBJECTS) $(LIBOBJECTS)

LIBRARY=libsofthsm
TESTS=cryptotest

# Include dependencies
-include $(OBJECTS:.o=.d)

# Include test dependencies
-include $(CRYPTOTESTOBJECTS:.o=.d)

all: $(SOURCES) $(HEADERS) $(LIBRARY) 

clean:
	rm -f *.d *.o $(LIBRARY) $(TESTS)

libsofthsm: $(SOURCES) $(HEADERS) $(OBJECTS)
	echo "No build rule for libsofthsm yet"

test: $(TESTS)

cryptotest: $(CRYPTOTESTSOURCES) $(CRYPTOTESTHEADERS) $(CRYPTOTESTOBJECTS)
	$(CPP) $(TESTLDFLAGS) $(CRYPTOTESTOBJECTS) -o $@

.cpp.o:
	$(CPP) $(CPPFLAGS) $< -c -o $@
	@$(CPP) -MM $(CPPFLAGS) $< > $*.d

.c.o:
	$(CC) $(CFLAGS) $< -c -o $@
	@$(CC) -MM $(CFLAGS) $< > $*.d
