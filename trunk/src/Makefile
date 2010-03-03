# Temporary Makefile that is used until this project has been auto'd by Rickard ;-)
#
# $Id$

CC=gcc
CFLAGS=-g -Wall -DWITH_OPENSSL

CPP=g++
CPPFLAGS=-g -Wall -DWITH_OPENSSL

LDFLAGS=

-include Makefile.crypto
-include Makefile.lib

SOURCES=$(CRYPTOSOURCES) $(LIBSOURCES)
HEADERS=$(CRYPTOHEADERS) $(LIBHEADERS)
OBJECTS=$(CRYPTOOBJECTS) $(LIBOBJECTS)

LIBRARY=libsofthsm

# Include dependencies
-include $(OBJECTS:.o=.d)

# Include test dependencies
-include $(CRYPTOTESTOBJECTS:.o=.d)

all: $(SOURCES) $(HEADERS) $(LIBRARY) 

clean:
	rm -f *.d *.o $(LIBRARY)

libsofthsm: $(SOURCES) $(HEADERS) $(OBJECTS)
	echo "No build rule for libsofthsm yet"

.cpp.o:
	$(CPP) $(CPPFLAGS) $< -c -o $@
	@$(CPP) -MM $(CPPFLAGS) $< > $*.d

.c.o:
	$(CC) $(CFLAGS) $< -c -o $@
	@$(CC) -MM $(CFLAGS) $< > $*.d
