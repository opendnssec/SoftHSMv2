# $Id$

MAINTAINERCLEANFILES = 		$(srcdir)/Makefile.in

AM_CPPFLAGS = 			-I$(srcdir)/.. \
				-I$(srcdir)/../.. \
				-I$(srcdir)/../../common \
				-I$(srcdir)/../../cryptoki_compat \
				-I$(srcdir)/../../crypto \
				-I$(srcdir)/../../object_store \
				-I$(srcdir)/../../session_mgr \
				-I$(srcdir)/../../data_mgr \
				-I$(srcdir)/../../user_mgr \
				`cppunit-config --cflags`

check_PROGRAMS =		slotmgrtest

slotmgrtest_SOURCES =		slotmgrtest.cpp \
				SlotManagerTests.cpp

slotmgrtest_LDADD =		../../libsofthsm_convarch.la 

slotmgrtest_LDFLAGS = 		-no-install `cppunit-config --libs`

TESTS = 			slotmgrtest

#EXTRA_DIST =			$(srcdir)/*.h
