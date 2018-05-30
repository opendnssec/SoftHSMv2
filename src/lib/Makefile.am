MAINTAINERCLEANFILES = 		$(srcdir)/Makefile.in

AM_CPPFLAGS =			-I$(srcdir)/common \
				-I$(srcdir)/crypto \
				-I$(srcdir)/data_mgr \
				-I$(srcdir)/handle_mgr \
				-I$(srcdir)/object_store \
				-I$(srcdir)/pkcs11 \
				-I$(srcdir)/session_mgr \
				-I$(srcdir)/slot_mgr \
				@CRYPTO_INCLUDES@

lib_LTLIBRARIES =		libsofthsm2.la

libsofthsm2_la_SOURCES =	access.cpp \
				main.cpp \
				P11Attributes.cpp \
				P11Objects.cpp \
				SoftHSM.cpp
libsofthsm2_la_LIBADD =		common/libsofthsm_common.la \
				crypto/libsofthsm_crypto.la \
				data_mgr/libsofthsm_datamgr.la \
				handle_mgr/libsofthsm_handlemgr.la \
				object_store/libsofthsm_objectstore.la \
				session_mgr/libsofthsm_sessionmgr.la \
				slot_mgr/libsofthsm_slotmgr.la
libsofthsm2_la_LDFLAGS =	-version-info @VERSION_INFO@ \
				-avoid-version -module

# Create a convenience library from all the other convenience library; this is
# necessary to resolve circular dependencies when statically linking the test
# executables
noinst_LTLIBRARIES =		libsofthsm_convarch.la

libsofthsm_convarch_la_SOURCES =

libsofthsm_convarch_la_LIBADD =	$(libsofthsm2_la_LIBADD)

SUBDIRS = 			common \
				crypto \
				data_mgr \
				object_store \
				session_mgr \
				slot_mgr \
				handle_mgr \
				test

EXTRA_DIST =			$(srcdir)/CMakeLists.txt \
				$(srcdir)/*.h \
				$(srcdir)/pkcs11/*.h \
				$(srcdir)/win32/*.cc \
				$(srcdir)/win32/*.cpp \
				$(srcdir)/win32/*.h
