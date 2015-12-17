MAINTAINERCLEANFILES = 		$(srcdir)/Makefile.in

AM_CPPFLAGS = 			-I$(srcdir)/.. \
				-I$(srcdir)/../.. \
				-I$(srcdir)/../../common \
				-I$(srcdir)/../../cryptoki_compat \
				-I$(srcdir)/../../crypto \
				-I$(srcdir)/../../object_store \
				-I$(srcdir)/../../session_mgr \
				-I$(srcdir)/../../slot_mgr \
				@CRYPTO_INCLUDES@ \
				`cppunit-config --cflags`

check_PROGRAMS =		datamgrtest

datamgrtest_SOURCES =		datamgrtest.cpp \
				ByteStringTests.cpp \
				RFC4880Tests.cpp \
				SecureDataMgrTests.cpp

datamgrtest_LDADD =		../../libsofthsm_convarch.la 

datamgrtest_LDFLAGS = 		@CRYPTO_LIBS@ -no-install `cppunit-config --libs`

TESTS = 			datamgrtest

EXTRA_DIST =			$(srcdir)/*.h
