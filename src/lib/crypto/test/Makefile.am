MAINTAINERCLEANFILES = 		$(srcdir)/Makefile.in

AM_CPPFLAGS = 			-I$(srcdir)/.. \
				-I$(srcdir)/../.. \
				-I$(srcdir)/../../common \
				-I$(srcdir)/../../cryptoki_compat \
				-I$(srcdir)/../../data_mgr \
				-I$(srcdir)/../../object_store \
				-I$(srcdir)/../../session_mgr \
				-I$(srcdir)/../../slot_mgr \
				@CRYPTO_INCLUDES@ \
				`cppunit-config --cflags`

check_PROGRAMS =		cryptotest

cryptotest_SOURCES =		cryptotest.cpp \
				AESTests.cpp \
				DESTests.cpp \
				DHTests.cpp \
				DSATests.cpp \
				ECDHTests.cpp \
				ECDSATests.cpp \
				GOSTTests.cpp \
				HashTests.cpp \
				MacTests.cpp \
				RNGTests.cpp \
				RSATests.cpp \
				chisq.c \
				ent.c \
				iso8859.c \
				randtest.c

cryptotest_LDADD =		../../libsofthsm_convarch.la

cryptotest_LDFLAGS = 		@CRYPTO_LIBS@ -no-install `cppunit-config --libs`

TESTS = 			cryptotest

EXTRA_DIST =			$(srcdir)/*.h
