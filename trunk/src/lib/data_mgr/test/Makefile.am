# $Id$

MAINTAINERCLEANFILES = 		$(srcdir)/Makefile.in

AM_CPPFLAGS = 			-I$(srcdir)/.. \
				-I$(srcdir)/../.. \
				-I$(srcdir)/../../common \
				-I$(srcdir)/../../cryptoki_compat \
				-I$(srcdir)/../../data_mgr \
				-I$(srcdir)/../../object_store \
				-I$(srcdir)/../../session_mgr \
				-I$(srcdir)/../../slot_mgr \
				-I$(srcdir)/../../user_mgr \
				`cppunit-config --cflags`

check_PROGRAMS =		datamgrtest
datamgrtest_SOURCES =		datamgrtest.cpp
datamgrtest_LDADD =		../../common/libsofthsm_common.la \
				../../crypto/libsofthsm_crypto.la \
				../../data_mgr/libsofthsm_datamgr.la \
				../../object_store/libsofthsm_objectstore.la \
				../../session_mgr/libsofthsm_sessionmgr.la \
				../../slot_mgr/libsofthsm_slotmgr.la \
				../../user_mgr/libsofthsm_usermgr.la
datamgrtest_LDFLAGS = 		-no-install `cppunit-config --libs`

TESTS = 			datamgrtest

EXTRA_DIST =			$(srcdir)/*.h
