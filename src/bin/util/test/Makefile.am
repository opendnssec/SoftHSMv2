MAINTAINERCLEANFILES = 		$(srcdir)/Makefile.in

TESTS_ENVIRONMENT =		top_builddir='$(top_builddir)' top_srcdir='$(top_srcdir)' srcdir='$(srcdir)' builddir='$(builddir)'

TESTS = 			mldsa44-import-key-test.sh mlkem512-import-key-test.sh p11prov-test.sh

check_SCRIPTS =			$(TESTS)

EXTRA_DIST =			$(srcdir)/CMakeLists.txt \
				$(srcdir)/test-common.sh \
				$(srcdir)/import-key-test-common.sh \
				$(srcdir)/mldsa44-import-key-test.sh \
				$(srcdir)/mlkem512-import-key-test.sh \
				$(srcdir)/p11prov-test.sh
