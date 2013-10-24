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
					Generation.cpp \
					OSAttribute.cpp \
					OSToken.cpp \
					ObjectFile.cpp \
					SessionObject.cpp \
					SessionObjectStore.cpp \
					FindOperation.cpp

SUBDIRS = 				test

EXTRA_DIST =				$(srcdir)/*.h
