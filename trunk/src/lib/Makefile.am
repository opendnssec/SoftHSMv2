# $Id$

MAINTAINERCLEANFILES = 		$(srcdir)/Makefile.in

AM_CPPFLAGS = 			-I$(srcdir)/cryptoki_compat \
				-I$(srcdir)/common \
				-I$(srcdir)/crypto

lib_LTLIBRARIES =		libsofthsm.la
libsofthsm_la_SOURCES =		main.cpp \
				SoftHSM.cpp
libsofthsm_la_LIBADD =		common/libsofthsm_common.la \
				crypto/libsofthsm_crypto.la \
				data_mgr/libsofthsm_datamgr.la \
				object_store/libsofthsm_objectstore.la \
				session_mgr/libsofthsm_sessionmgr.la \
				slot_mgr/libsofthsm_slotmgr.la \
				user_mgr/libsofthsm_usermgr.la
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
