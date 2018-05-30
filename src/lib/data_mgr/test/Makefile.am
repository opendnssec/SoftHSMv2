MAINTAINERCLEANFILES = 		$(srcdir)/Makefile.in

AM_CPPFLAGS = 			-I$(srcdir)/.. \
				-I$(srcdir)/../.. \
				-I$(srcdir)/../../common \
				-I$(srcdir)/../../crypto \
				-I$(srcdir)/../../object_store \
				-I$(srcdir)/../../pkcs11 \
				-I$(srcdir)/../../session_mgr \
				-I$(srcdir)/../../slot_mgr \
				@CPPUNIT_CFLAGS@ \
				@CRYPTO_INCLUDES@

check_PROGRAMS =		datamgrtest

datamgrtest_SOURCES =		datamgrtest.cpp \
				ByteStringTests.cpp \
				RFC4880Tests.cpp \
				SecureDataMgrTests.cpp

datamgrtest_LDADD =		../../libsofthsm_convarch.la

datamgrtest_LDFLAGS = 		@CRYPTO_LIBS@ @CPPUNIT_LIBS@ -no-install

TESTS = 			datamgrtest

EXTRA_DIST =			$(srcdir)/CMakeLists.txt \
				$(srcdir)/*.h
