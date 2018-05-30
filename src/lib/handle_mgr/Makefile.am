MAINTAINERCLEANFILES = 			$(srcdir)/Makefile.in

AM_CPPFLAGS =				-I$(srcdir)/.. \
					-I$(srcdir)/../common \
					-I$(srcdir)/../crypto \
					-I$(srcdir)/../data_mgr \
					-I$(srcdir)/../object_store \
					-I$(srcdir)/../pkcs11 \
					-I$(srcdir)/../slot_mgr

noinst_LTLIBRARIES =			libsofthsm_handlemgr.la
libsofthsm_handlemgr_la_SOURCES =	HandleManager.cpp \
					Handle.cpp

SUBDIRS =				test

EXTRA_DIST =				$(srcdir)/CMakeLists.txt \
					$(srcdir)/*.h
