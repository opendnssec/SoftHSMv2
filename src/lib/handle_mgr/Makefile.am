MAINTAINERCLEANFILES = 			$(srcdir)/Makefile.in

AM_CPPFLAGS =				-I$(srcdir)/../cryptoki_compat \
					-I$(srcdir)/../slot_mgr \
					-I$(srcdir)/../data_mgr \
					-I$(srcdir)/../object_store \
					-I$(srcdir)/../crypto \
					-I$(srcdir)/../common \
					-I$(srcdir)/..

noinst_LTLIBRARIES =			libsofthsm_handlemgr.la
libsofthsm_handlemgr_la_SOURCES =	HandleManager.cpp \
					Handle.cpp

SUBDIRS =				test

EXTRA_DIST =				$(srcdir)/*.h
