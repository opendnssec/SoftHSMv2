# $Id: Makefile.am 32 2010-03-05 13:10:43Z rb $

MAINTAINERCLEANFILES = 		$(srcdir)/Makefile.in

AM_CPPFLAGS =                   -I$(srcdir)/../cryptoki_compat \
				-I$(srcdir)/../crypto \
				-I$(srcdir)/../data_mgr

noinst_LTLIBRARIES =		libcommon.la
libcommon_la_SOURCES =		Configuration.cpp \
				fatal.cpp \
				log.cpp \
				osmutex.cpp \
				XMLConfigLoader.cpp

EXTRA_DIST =			$(srcdir)/*.h
