# $Id$

MAINTAINERCLEANFILES =	$(srcdir)/Makefile.in

AM_CPPFLAGS = 		-I$(srcdir)/../../lib/cryptoki_compat \
			@SQLITE3_INCLUDES@

dist_man_MANS =		softhsm-migrate.1

bin_PROGRAMS =		softhsm-migrate

softhsm_migrate_SOURCES =	softhsm-migrate.cpp
softhsm_migrate_LDADD =		@SQLITE3_LIBS@ \
				@YIELD_LIB@

EXTRA_DIST =		$(srcdir)/*.h
