MAINTAINERCLEANFILES = 		$(srcdir)/Makefile.in

AM_CPPFLAGS = 			-I$(srcdir)/.. \
				-I$(srcdir)/../.. \
				-I$(srcdir)/../../common \
				-I$(srcdir)/../../cryptoki_compat \
				-I$(srcdir)/../../crypto \
				-I$(srcdir)/../../data_mgr \
				-I$(srcdir)/../../session_mgr \
				-I$(srcdir)/../../slot_mgr \
				@CRYPTO_INCLUDES@ \
				`cppunit-config --cflags`

check_PROGRAMS =		objstoretest

objstoretest_SOURCES =		objstoretest.cpp \
				DirectoryTests.cpp \
				UUIDTests.cpp \
				FileTests.cpp \
				ObjectFileTests.cpp \
				OSTokenTests.cpp \
				ObjectStoreTests.cpp \
				SessionObjectTests.cpp \
				SessionObjectStoreTests.cpp

if BUILD_OBJECTSTORE_BACKEND_DB
objstoretest_SOURCES +=		DBTests.cpp \
				DBObjectTests.cpp \
				DBTokenTests.cpp \
				DBObjectStoreTests.cpp
endif

objstoretest_LDADD =		../../libsofthsm_convarch.la 

objstoretest_LDFLAGS = 		@CRYPTO_LIBS@ -no-install `cppunit-config --libs` -pthread

TESTS = 			objstoretest

EXTRA_DIST =			$(srcdir)/*.h
