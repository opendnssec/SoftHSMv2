MAINTAINERCLEANFILES =	$(srcdir)/Makefile.in

AM_CPPFLAGS = 		-I$(srcdir)/../../lib/pkcs11 \
			-I$(srcdir)/../common \
			@SQLITE3_INCLUDES@

dist_man_MANS =		softhsm2-migrate.1

bin_PROGRAMS =		softhsm2-migrate

AUTOMAKE_OPTIONS =	subdir-objects

softhsm2_migrate_SOURCES =	softhsm2-migrate.cpp \
				../common/findslot.cpp \
				../common/getpw.cpp \
				../common/library.cpp
softhsm2_migrate_LDADD =	@SQLITE3_LIBS@ \
				@YIELD_LIB@

EXTRA_DIST =		$(srcdir)/CMakeLists.txt \
			$(srcdir)/*.h
