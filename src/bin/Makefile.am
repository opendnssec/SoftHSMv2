MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

SUBDIRS = common keyconv util dump

if BUILD_MIGRATE
SUBDIRS += migrate
endif

EXTRA_DIST =	$(srcdir)/CMakeLists.txt \
		$(srcdir)/win32/*.cpp \
		$(srcdir)/win32/*.h
