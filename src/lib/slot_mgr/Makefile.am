MAINTAINERCLEANFILES = 		$(srcdir)/Makefile.in

AM_CPPFLAGS =			-I$(srcdir)/../cryptoki_compat \
				-I$(srcdir)/../crypto \
				-I$(srcdir)/../common \
				-I$(srcdir)/../data_mgr \
				-I$(srcdir)/../session_mgr \
				-I$(srcdir)/../object_store \
				-I$(srcdir)/..

noinst_LTLIBRARIES =		libsofthsm_slotmgr.la
libsofthsm_slotmgr_la_SOURCES =	SlotManager.cpp \
				Slot.cpp \
				Token.cpp

SUBDIRS =			test

EXTRA_DIST =			$(srcdir)/*.h
