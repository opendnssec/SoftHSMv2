MAINTAINERCLEANFILES = 		$(srcdir)/Makefile.in

AM_CPPFLAGS = 			-I$(srcdir)/.. \
				-I$(srcdir)/../.. \
				-I$(srcdir)/../../common \
				-I$(srcdir)/../../cryptoki_compat \
				-I$(srcdir)/../../crypto \
				-I$(srcdir)/../../object_store \
				-I$(srcdir)/../../session_mgr \
				-I$(srcdir)/../../data_mgr \
				@CRYPTO_INCLUDES@

AM_CFLAGS =			@CPPUNIT_CFLAGS@

check_PROGRAMS =		slotmgrtest

slotmgrtest_SOURCES =		slotmgrtest.cpp \
				SlotManagerTests.cpp

slotmgrtest_LDADD =		../../libsofthsm_convarch.la 

slotmgrtest_LDFLAGS = 		@CRYPTO_LIBS@ @CPPUNIT_LIBS@ -no-install -pthread

TESTS = 			slotmgrtest

EXTRA_DIST =			$(srcdir)/*.h
