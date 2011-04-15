# $Id: Makefile.am 32 2010-03-05 13:10:43Z rb $

MAINTAINERCLEANFILES = 		$(srcdir)/Makefile.in

AM_CPPFLAGS =                   -I$(srcdir)/../cryptoki_compat \
				-I$(srcdir)/../crypto \
				-I$(srcdir)/../data_mgr \
				-I$(srcdir)/..

noinst_LTLIBRARIES =		libsofthsm_common.la
libsofthsm_common_la_SOURCES =	Configuration.cpp \
				fatal.cpp \
				log.cpp \
				osmutex.cpp \
				SimpleConfigLoader.cpp \
				MutexFactory.cpp \
				Semaphore.cpp \
				IPCSignal.cpp
libsofthsm_common_la_LIBADD =	@SEMAPHORE_LIB@

EXTRA_DIST =			$(srcdir)/*.h

install-data-hook:
	test -d ${DESTDIR}${sysconfdir} || \
		${INSTALL} -d ${DESTDIR}${sysconfdir}
	test -f ${DESTDIR}${sysconfdir}/softhsm2.conf || \
		${INSTALL_DATA} ${top_builddir}/softhsm2.conf ${DESTDIR}${sysconfdir}
	${INSTALL_DATA} ${top_builddir}/softhsm2.conf ${DESTDIR}${sysconfdir}/softhsm2.conf.sample
	test -d ${DESTDIR}${softhsmtokendir} || \
		${INSTALL} -d -m 700 ${DESTDIR}${softhsmtokendir}
