# $Id$

MAINTAINERCLEANFILES = 		$(srcdir)/Makefile.in

AM_CPPFLAGS = 			-I$(srcdir)/cryptoki_compat \
				-I$(srcdir)/common \
				-I$(srcdir)/crypto

lib_LTLIBRARIES =		libsofthsm.la
libsofthsm_la_SOURCES =		main.cpp \
				SoftHSM.cpp
libsofthsm_la_LIBADD =		common/libcommon.la \
				crypto/libcrypto.la \
				data_mgr/libdatamgr.la \
				object_store/libobjectstore.la \
				session_mgr/libsessionmgr.la \
				slot_mgr/libslotmgr.la \
				user_mgr/libusermgr.la
libsofthsm_la_LDFLAGS =		-version-info @VERSION_INFO@ \
				-avoid-version -module

SUBDIRS = 			common \
				crypto \
				data_mgr \
				object_store \
				session_mgr \
				slot_mgr \
				user_mgr

EXTRA_DIST =			$(srcdir)/*.h \
				$(srcdir)/cryptoki_compat/*.h
