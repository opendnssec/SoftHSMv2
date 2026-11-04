MAINTAINERCLEANFILES = 		$(srcdir)/Makefile.in

TESTS_ENVIRONMENT =		top_builddir='$(top_builddir)' top_srcdir='$(top_srcdir)' srcdir='$(srcdir)' builddir='$(builddir)'

TESTS = 			mldsa44-import-key-test.sh mlkem512-import-key-test.sh

if WITH_FALCON
TESTS += falcon512-import-key-test.sh falcon1024-import-key-test.sh
endif

check_SCRIPTS =			$(TESTS)

EXTRA_DIST =			$(srcdir)/CMakeLists.txt \
				$(srcdir)/import-key-test-common.sh \
				$(srcdir)/mldsa44-import-key-test.sh \
				$(srcdir)/mlkem512-import-key-test.sh

EXTRA_DIST += $(srcdir)/falcon512-import-key-test.sh $(srcdir)/falcon1024-import-key-test.sh
