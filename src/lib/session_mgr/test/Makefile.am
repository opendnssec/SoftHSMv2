MAINTAINERCLEANFILES = 		$(srcdir)/Makefile.in

AM_CPPFLAGS = 			-I$(srcdir)/.. \
				-I$(srcdir)/../.. \
				-I$(srcdir)/../../common \
				-I$(srcdir)/../../cryptoki_compat \
				-I$(srcdir)/../../crypto \
				-I$(srcdir)/../../data_mgr \
				-I$(srcdir)/../../session_mgr \
				-I$(srcdir)/../../slot_mgr \
				-I$(srcdir)/../../object_store

AM_CFLAGS =			@CPPUNIT_CFLAGS@

check_PROGRAMS =		sessionmgrtest

sessionmgrtest_SOURCES =	sessionmgrtest.cpp \
				SessionManagerTests.cpp

sessionmgrtest_LDADD =		../../libsofthsm_convarch.la 

sessionmgrtest_LDFLAGS =	@CRYPTO_LIBS@ @CPPUNIT_LIBS@ -no-install -pthread

TESTS = 			sessionmgrtest

EXTRA_DIST =			$(srcdir)/*.h
