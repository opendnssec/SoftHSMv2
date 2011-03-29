# $Id: Makefile.am 32 2010-03-05 13:10:43Z rb $

MAINTAINERCLEANFILES = 		$(srcdir)/Makefile.in

AM_CPPFLAGS = 			-I$(srcdir)/.. \
				-I$(srcdir)/../.. \
				-I$(srcdir)/../../common \
				-I$(srcdir)/../../cryptoki_compat \
				-I$(srcdir)/../../data_mgr \
				-I$(srcdir)/../../object_store \
				-I$(srcdir)/../../session_mgr \
				-I$(srcdir)/../../slot_mgr \
				`cppunit-config --cflags`

check_PROGRAMS =		cryptotest

cryptotest_SOURCES =		cryptotest.cpp \
				AESTests.cpp \
				DESTests.cpp \
				DSATests.cpp \
				HashTests.cpp \
				RNGTests.cpp \
				RSATests.cpp \
				chisq.c \
				ent.c \
				iso8859.c \
				randtest.c

cryptotest_LDADD =		../../libsofthsm_convarch.la

cryptotest_LDFLAGS = 		-no-install `cppunit-config --libs`

TESTS = 			cryptotest

EXTRA_DIST =			$(srcdir)/*.h
