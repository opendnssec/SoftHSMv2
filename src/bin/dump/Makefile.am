MAINTAINERCLEANFILES =	$(srcdir)/Makefile.in

AM_CPPFLAGS =		-I$(srcdir)/../../lib \
			-I$(srcdir)/../../lib/object_store \
			-I$(srcdir)/../../lib/pkcs11 \
			@SQLITE3_INCLUDES@

dist_man_MANS =		softhsm2-dump-file.1

bin_PROGRAMS =		softhsm2-dump-file

if BUILD_OBJECTSTORE_BACKEND_DB
dist_man_MANS +=	softhsm2-dump-db.1
bin_PROGRAMS +=		softhsm2-dump-db
endif

softhsm2_dump_file_SOURCES =	softhsm2-dump-file.cpp

softhsm2_dump_db_SOURCES = softhsm2-dump-db.cpp

softhsm2_dump_db_LDADD	= @SQLITE3_LIBS@ @YIELD_LIB@

EXTRA_DIST =		$(srcdir)/CMakeLists.txt \
			$(srcdir)/*.h \
			softhsm2-dump-db.1
