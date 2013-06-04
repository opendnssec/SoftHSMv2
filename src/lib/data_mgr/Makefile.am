MAINTAINERCLEANFILES = 		$(srcdir)/Makefile.in

AM_CPPFLAGS =			-I$(srcdir)/../cryptoki_compat \
				-I$(srcdir)/../crypto \
				-I$(srcdir)/../common \
				-I$(srcdir)/..

noinst_LTLIBRARIES =		libsofthsm_datamgr.la
libsofthsm_datamgr_la_SOURCES =	ByteString.cpp \
				RFC4880.cpp \
				salloc.cpp \
				SecureDataManager.cpp \
				SecureMemoryRegistry.cpp

SUBDIRS =			test

EXTRA_DIST =			$(srcdir)/*.h
