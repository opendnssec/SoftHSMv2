# $Id$

MAINTAINERCLEANFILES = 		$(srcdir)/Makefile.in

AM_CPPFLAGS = 			-I$(srcdir)/.. \
				-I$(srcdir)/../cryptoki_compat \
				-I$(srcdir)/../common \
				`cppunit-config --cflags`

check_PROGRAMS =		p11test

p11test_SOURCES =		p11test.cpp \
				InitTests.cpp \
				../common/osmutex.cpp

p11test_LDADD =			../libsofthsm.la 

p11test_LDFLAGS = 		-no-install `cppunit-config --libs` -pthread -static

TESTS = 			p11test

EXTRA_DIST =			$(srcdir)/*.h
