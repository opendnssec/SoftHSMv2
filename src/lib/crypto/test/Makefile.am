MAINTAINERCLEANFILES = 		$(srcdir)/Makefile.in

AM_CPPFLAGS = 			-I$(srcdir)/.. \
				-I$(srcdir)/../.. \
				-I$(srcdir)/../../common \
				-I$(srcdir)/../../data_mgr \
				-I$(srcdir)/../../object_store \
				-I$(srcdir)/../../pkcs11 \
				-I$(srcdir)/../../session_mgr \
				-I$(srcdir)/../../slot_mgr \
				@CPPUNIT_CFLAGS@ \
				@CRYPTO_INCLUDES@

check_PROGRAMS =		cryptotest

cryptotest_SOURCES =		cryptotest.cpp \
				AESTests.cpp \
				DESTests.cpp \
				DHTests.cpp \
				DSATests.cpp \
				ECDHTests.cpp \
				ECDSATests.cpp \
				EDDSATests.cpp \
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

cryptotest_LDFLAGS = 		@CRYPTO_LIBS@ @CPPUNIT_LIBS@ -no-install

TESTS = 			cryptotest

EXTRA_DIST =			$(srcdir)/CMakeLists.txt \
				$(srcdir)/*.h
