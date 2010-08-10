# $Id$

MAINTAINERCLEANFILES =	$(srcdir)/Makefile.in

AM_CPPFLAGS = 		-I$(srcdir)/../../lib/cryptoki_compat \
			-I$(srcdir)/../common \
			@SQLITE3_INCLUDES@

dist_man_MANS =		softhsm-migrate.1

bin_PROGRAMS =		softhsm-migrate

softhsm_migrate_SOURCES =	softhsm-migrate.cpp \
				../common/getpw.cpp \
				../common/library.cpp
softhsm_migrate_LDADD =		@SQLITE3_LIBS@ \
				@YIELD_LIB@

EXTRA_DIST =		$(srcdir)/*.h
