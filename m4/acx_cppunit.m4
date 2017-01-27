AC_DEFUN([ACX_CPPUNIT],[
	PKG_PROG_PKG_CONFIG
	PKG_CHECK_MODULES([CPPUNIT], [cppunit], [have_cppunit=yes], [have_cppunit=no])
])
