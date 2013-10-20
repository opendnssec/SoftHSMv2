MAINTAINERCLEANFILES =	$(srcdir)/Makefile.in

AM_CPPFLAGS = 		-I$(srcdir)/../../lib/cryptoki_compat \
			-I$(srcdir)/../../lib/object_store \
			-I$(srcdir)/../../lib

dist_man_MANS =		softhsm-dump.1

bin_PROGRAMS =		softhsm-dump

softhsm_dump_SOURCES =	softhsm-dump.cpp

EXTRA_DIST =		$(srcdir)/*.h
