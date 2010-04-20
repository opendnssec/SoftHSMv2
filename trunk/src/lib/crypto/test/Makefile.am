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
				-I$(srcdir)/../../user_mgr \
				`cppunit-config --cflags`

check_PROGRAMS =		cryptotest
cryptotest_SOURCES =		cryptotest.cpp \
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
cryptotest_LDADD =		../../common/libsofthsm_common.la \
				../libsofthsm_crypto.la \
				../../data_mgr/libsofthsm_datamgr.la \
				../../object_store/libsofthsm_objectstore.la \
				../../session_mgr/libsofthsm_sessionmgr.la \
				../../slot_mgr/libsofthsm_slotmgr.la \
				../../user_mgr/libsofthsm_usermgr.la
cryptotest_LDFLAGS = 		-no-install `cppunit-config --libs`

TESTS = 			cryptotest

EXTRA_DIST =			$(srcdir)/*.h
