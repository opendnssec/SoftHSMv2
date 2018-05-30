MAINTAINERCLEANFILES = 		$(srcdir)/Makefile.in

AM_CPPFLAGS = 			-I$(srcdir)/.. \
				-I$(srcdir)/../.. \
				-I$(srcdir)/../../common \
				-I$(srcdir)/../../crypto \
				-I$(srcdir)/../../data_mgr \
				-I$(srcdir)/../../pkcs11 \
				-I$(srcdir)/../../session_mgr \
				-I$(srcdir)/../../slot_mgr \
				@CPPUNIT_CFLAGS@ \
				@CRYPTO_INCLUDES@

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

objstoretest_LDFLAGS = 		@CRYPTO_LIBS@ @CPPUNIT_LIBS@ -no-install -pthread

TESTS = 			objstoretest

EXTRA_DIST =			$(srcdir)/CMakeLists.txt \
				$(srcdir)/*.h
