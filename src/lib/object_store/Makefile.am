MAINTAINERCLEANFILES = 			$(srcdir)/Makefile.in

AM_CPPFLAGS =				-I$(srcdir)/../cryptoki_compat \
					-I$(srcdir)/../crypto \
					-I$(srcdir)/../data_mgr \
					-I$(srcdir)/../common \
					-I$(srcdir)/.. \
					@SQLITE3_INCLUDES@

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
					FindOperation.cpp \
					ObjectStoreToken.cpp \
					DB.cpp \
					DBObject.cpp \
					DBToken.cpp

libsofthsm_objectstore_la_LDFLAGS =	@SQLITE3_LIBS@

SUBDIRS = 				test

EXTRA_DIST =				$(srcdir)/*.h
