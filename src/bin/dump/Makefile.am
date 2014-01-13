MAINTAINERCLEANFILES =	$(srcdir)/Makefile.in

AM_CPPFLAGS = 		-I$(srcdir)/../../lib/cryptoki_compat \
			-I$(srcdir)/../../lib/object_store \
			-I$(srcdir)/../../lib \
			@SQLITE3_INCLUDES@

dist_man_MANS =		softhsm-dump-file.1 softhsm-dump-db.1

bin_PROGRAMS =		softhsm-dump-file

if BUILD_OBJECTSTORE_BACKEND_DB
bin_PROGRAMS +=		softhsm-dump-db
endif

softhsm_dump_file_SOURCES =	softhsm-dump-file.cpp

softhsm_dump_db_SOURCES = softhsm-dump-db.cpp

softhsm_dump_db_LDADD	= @SQLITE3_LIBS@ @YIELD_LIB@

EXTRA_DIST =		$(srcdir)/*.h
