AC_DEFUN([ACX_CPPUNIT],[
	AC_PATH_PROG([CPPUNIT_CONFIG], [cppunit-config])
	AC_PATH_PROG([PKG_CONFIG], [pkg-config])
	if test -n "${CPPUNIT_CONFIG}"; then
		AC_MSG_CHECKING([cppunit cflags])
		CPPUNIT_CFLAGS=`${CPPUNIT_CONFIG} --cflags`
		AC_MSG_RESULT([${CPPUNIT_CFLAGS}])
		AC_MSG_CHECKING([cppunit libs])
		CPPUNIT_LIBS=`${CPPUNIT_CONFIG} --libs`
		AC_MSG_RESULT([${CPPUNIT_LIBS}])
	elif test -n "${PKG_CONFIG}"; then
		AC_MSG_CHECKING([cppunit cflags])
		CPPUNIT_CFLAGS=`${PKG_CONFIG} cppunit --cflags`
		AC_MSG_RESULT([${CPPUNIT_CFLAGS}])
		AC_MSG_CHECKING([cppunit libs])
		CPPUNIT_LIBS=`${PKG_CONFIG} cppunit --libs`
		AC_MSG_RESULT([${CPPUNIT_LIBS}])
	fi
	AC_SUBST([CPPUNIT_CFLAGS])
	AC_SUBST([CPPUNIT_LIBS])
])
