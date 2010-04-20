# $Id: Makefile.am 32 2010-03-05 13:10:43Z rb $

MAINTAINERCLEANFILES = 		$(srcdir)/Makefile.in

AM_CPPFLAGS =			-I$(srcdir)/../cryptoki_compat \
				-I$(srcdir)/../crypto \
				-I$(srcdir)/../common

noinst_LTLIBRARIES =		libsofthsm_datamgr.la
libsofthsm_datamgr_la_SOURCES =	ByteString.cpp \
				salloc.cpp \
				SecureMemoryRegistry.cpp

EXTRA_DIST =			$(srcdir)/*.h
