# $Id: Makefile.am 32 2010-03-05 13:10:43Z rb $

MAINTAINERCLEANFILES = 			$(srcdir)/Makefile.in

AM_CPPFLAGS =				-I$(srcdir)/../cryptoki_compat \
					-I$(srcdir)/../slot_mgr \
					-I$(srcdir)/../data_mgr \
					-I$(srcdir)/../object_store \
					-I$(srcdir)/../crypto \
					-I$(srcdir)/../common \
					-I$(srcdir)/..

noinst_LTLIBRARIES =			libsofthsm_sessionmgr.la
libsofthsm_sessionmgr_la_SOURCES =	SessionManager.cpp \
					Session.cpp

EXTRA_DIST =				$(srcdir)/*.h
