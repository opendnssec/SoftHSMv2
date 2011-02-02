# $Id$

MAINTAINERCLEANFILES = 		$(srcdir)/Makefile.in

AM_CPPFLAGS = 			-I$(srcdir)/cryptoki_compat \
				-I$(srcdir)/common \
				-I$(srcdir)/object_store \
				-I$(srcdir)/slot_mgr \
				-I$(srcdir)/session_mgr \
				-I$(srcdir)/data_mgr \
				-I$(srcdir)/crypto

lib_LTLIBRARIES =		libsofthsm.la

libsofthsm_la_SOURCES =		access.cpp \
				main.cpp \
				P11Attributes.cpp \
				P11Objects.cpp \
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

# Create a convenience library from all the other convenience library; this is
# necessary to resolve circular dependencies when statically linking the test
# executables
noinst_LTLIBRARIES =		libsofthsm_convarch.la

libsofthsm_convarch_la_SOURCES =

libsofthsm_convarch_la_LIBADD =	$(libsofthsm_la_LIBADD)

SUBDIRS = 			common \
				crypto \
				data_mgr \
				object_store \
				session_mgr \
				slot_mgr \
				test \
				user_mgr

EXTRA_DIST =			$(srcdir)/*.h \
				$(srcdir)/cryptoki_compat/*.h
