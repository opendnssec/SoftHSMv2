MAINTAINERCLEANFILES = 		$(srcdir)/Makefile.in

AM_CPPFLAGS = 			-I$(srcdir)/.. \
				-I$(srcdir)/../.. \
				-I$(srcdir)/../../common \
				-I$(srcdir)/../../crypto \
				-I$(srcdir)/../../data_mgr \
				-I$(srcdir)/../../object_store \
				-I$(srcdir)/../../pkcs11 \
				-I$(srcdir)/../../session_mgr \
				@CPPUNIT_CFLAGS@ \
				@CRYPTO_INCLUDES@

check_PROGRAMS =		slotmgrtest

slotmgrtest_SOURCES =		slotmgrtest.cpp \
				SlotManagerTests.cpp

slotmgrtest_LDADD =		../../libsofthsm_convarch.la

slotmgrtest_LDFLAGS = 		@CRYPTO_LIBS@ @CPPUNIT_LIBS@ -no-install -pthread

TESTS = 			slotmgrtest

EXTRA_DIST =			$(srcdir)/CMakeLists.txt \
				$(srcdir)/*.h
