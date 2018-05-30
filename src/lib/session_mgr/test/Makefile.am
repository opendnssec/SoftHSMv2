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
				@CPPUNIT_CFLAGS@ \
				@CRYPTO_INCLUDES@

check_PROGRAMS =		sessionmgrtest

sessionmgrtest_SOURCES =	sessionmgrtest.cpp \
				SessionManagerTests.cpp

sessionmgrtest_LDADD =		../../libsofthsm_convarch.la

sessionmgrtest_LDFLAGS =	@CRYPTO_LIBS@ @CPPUNIT_LIBS@ -no-install -pthread

TESTS = 			sessionmgrtest

EXTRA_DIST =			$(srcdir)/CMakeLists.txt \
				$(srcdir)/*.h
