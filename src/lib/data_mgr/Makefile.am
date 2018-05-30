MAINTAINERCLEANFILES = 		$(srcdir)/Makefile.in

AM_CPPFLAGS =			-I$(srcdir)/.. \
				-I$(srcdir)/../crypto \
				-I$(srcdir)/../common \
				-I$(srcdir)/../pkcs11

noinst_LTLIBRARIES =		libsofthsm_datamgr.la
libsofthsm_datamgr_la_SOURCES =	ByteString.cpp \
				RFC4880.cpp \
				salloc.cpp \
				SecureDataManager.cpp \
				SecureMemoryRegistry.cpp

SUBDIRS =			test

EXTRA_DIST =			$(srcdir)/CMakeLists.txt \
				$(srcdir)/*.h
