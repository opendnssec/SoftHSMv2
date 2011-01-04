# $Id: Makefile.am 32 2010-03-05 13:10:43Z rb $

MAINTAINERCLEANFILES = 			$(srcdir)/Makefile.in

AM_CPPFLAGS =				-I$(srcdir)/../cryptoki_compat \
					-I$(srcdir)/../crypto \
					-I$(srcdir)/../data_mgr \
					-I$(srcdir)/../common \
					-I$(srcdir)/..

noinst_LTLIBRARIES =			libsofthsm_objectstore.la
libsofthsm_objectstore_la_SOURCES =	ObjectStore.cpp \
					UUID.cpp \
					Directory.cpp \
					File.cpp \
					OSAttribute.cpp \
					OSObjectControl.cpp \
					OSToken.cpp \
					ObjectFile.cpp \
					SessionObject.cpp \
					SessionObjectStore.cpp

SUBDIRS = 				test

EXTRA_DIST =				$(srcdir)/*.h
