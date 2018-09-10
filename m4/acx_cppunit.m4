AC_DEFUN([ACX_CPPUNIT],[
	AC_PATH_PROG([CPPUNIT_CONFIG], [cppunit-config])
	if test -n "${PKG_CONFIG}"; then
		PKG_CHECK_MODULES([CPPUNIT], [cppunit], [], [:])
	elif test -n "${CPPUNIT_CONFIG}"; then
		AC_MSG_CHECKING([cppunit cflags])
		CPPUNIT_CFLAGS=`${CPPUNIT_CONFIG} --cflags`
		AC_MSG_RESULT([${CPPUNIT_CFLAGS}])
		AC_MSG_CHECKING([cppunit libs])
		CPPUNIT_LIBS=`${CPPUNIT_CONFIG} --libs`
		AC_MSG_RESULT([${CPPUNIT_LIBS}])
		AC_SUBST([CPPUNIT_CFLAGS])
		AC_SUBST([CPPUNIT_LIBS])
	fi
])
