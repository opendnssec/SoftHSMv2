# $Id: Makefile.am 32 2010-03-05 13:10:43Z rb $

MAINTAINERCLEANFILES = 		$(srcdir)/Makefile.in

AM_CPPFLAGS =                   -I$(srcdir)/../cryptoki_compat \
				-I$(srcdir)/../crypto \
				-I$(srcdir)/../data_mgr \
				-I$(srcdir)/..

noinst_LTLIBRARIES =		libsofthsm_common.la
libsofthsm_common_la_SOURCES =	Configuration.cpp \
				fatal.cpp \
				log.cpp \
				osmutex.cpp \
				XMLConfigLoader.cpp \
				MutexFactory.cpp \
				Semaphore.cpp \
				IPCSignal.cpp
libsofthsm_common_la_LIBADD =	@SEMAPHORE_LIB@

EXTRA_DIST =			$(srcdir)/*.h
