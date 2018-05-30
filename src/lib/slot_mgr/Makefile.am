MAINTAINERCLEANFILES = 		$(srcdir)/Makefile.in

AM_CPPFLAGS =			-I$(srcdir)/.. \
				-I$(srcdir)/../common \
				-I$(srcdir)/../crypto \
				-I$(srcdir)/../data_mgr \
				-I$(srcdir)/../object_store \
				-I$(srcdir)/../pkcs11 \
				-I$(srcdir)/../session_mgr

noinst_LTLIBRARIES =		libsofthsm_slotmgr.la
libsofthsm_slotmgr_la_SOURCES =	SlotManager.cpp \
				Slot.cpp \
				Token.cpp

SUBDIRS =			test

EXTRA_DIST =			$(srcdir)/CMakeLists.txt \
				$(srcdir)/*.h
