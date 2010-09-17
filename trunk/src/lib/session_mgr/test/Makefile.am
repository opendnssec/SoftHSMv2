# $Id$

MAINTAINERCLEANFILES = 		$(srcdir)/Makefile.in

AM_CPPFLAGS = 			-I$(srcdir)/.. \
				-I$(srcdir)/../.. \
				-I$(srcdir)/../../common \
				-I$(srcdir)/../../cryptoki_compat \
				-I$(srcdir)/../../crypto \
				-I$(srcdir)/../../data_mgr \
				-I$(srcdir)/../../session_mgr \
				-I$(srcdir)/../../slot_mgr \
				-I$(srcdir)/../../user_mgr \
				`cppunit-config --cflags`

check_PROGRAMS =		sessionmgrtest

sessionmgrtest_SOURCES =	sessionmgrtest.cpp

sessionmgrtest_LDADD =		../../libsofthsm_convarch.la 

sessionmgrtest_LDFLAGS =	-no-install `cppunit-config --libs` -pthread

TESTS = 			sessionmgrtest

EXTRA_DIST =			$(srcdir)/*.h
