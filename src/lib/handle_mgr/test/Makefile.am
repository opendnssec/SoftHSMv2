MAINTAINERCLEANFILES = 		$(srcdir)/Makefile.in

AM_CPPFLAGS = 			-I$(srcdir)/.. \
				-I$(srcdir)/../.. \
				-I$(srcdir)/../../common \
				-I$(srcdir)/../../crypto \
				-I$(srcdir)/../../data_mgr \
				-I$(srcdir)/../../object_store \
				-I$(srcdir)/../../pkcs11 \
				-I$(srcdir)/../../session_mgr \
				-I$(srcdir)/../../slot_mgr \
				@CPPUNIT_CFLAGS@

check_PROGRAMS =		handlemgrtest

handlemgrtest_SOURCES =		handlemgrtest.cpp \
				HandleManagerTests.cpp

handlemgrtest_LDADD =		../../libsofthsm_convarch.la

handlemgrtest_LDFLAGS = 	@CRYPTO_LIBS@ @CPPUNIT_LIBS@ -no-install

TESTS = 			handlemgrtest

EXTRA_DIST =			$(srcdir)/CMakeLists.txt \
				$(srcdir)/*.h

