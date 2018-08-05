AC_DEFUN([ACX_SQLITE3],[
	AC_ARG_WITH(sqlite3,
        	AC_HELP_STRING([--with-sqlite3=PATH],[Specify prefix of path of SQLite3]),
		[
			SQLITE3_INCLUDES="-I$withval/include"
			SQLITE3_LIBDIRS="-L$withval/lib"
			AC_PATH_PROGS(SQLITE3, sqlite3, sqlite3, $withval/bin)
			
		],[
			SQLITE3_INCLUDES=""
			SQLITE3_LIBDIRS=""
			AC_PATH_PROGS(SQLITE3, sqlite3, sqlite3, $PATH)
		])

	
	if ! test -x "$SQLITE3"; then
		AC_MSG_ERROR([sqlite3 command not found])
	fi
	
	AC_MSG_CHECKING(what are the SQLite3 includes)
	AC_MSG_RESULT($SQLITE3_INCLUDES)

	AC_MSG_CHECKING(what are the SQLite3 libs)
	SQLITE3_LIBS="$SQLITE3_LIBDIRS -lsqlite3"
	AC_MSG_RESULT($SQLITE3_LIBS)

	tmp_CPPFLAGS=$CPPFLAGS
	tmp_LIBS=$LIBS

	CPPFLAGS="$CPPFLAGS $SQLITE3_INCLUDES"
	LIBS="$LIBS $SQLITE3_LIBS"

	AC_CHECK_HEADERS(sqlite3.h,,[AC_MSG_ERROR([Can't find SQLite3 headers])])
	AC_CHECK_LIB(sqlite3, sqlite3_prepare_v2, [], [AC_MSG_ERROR([Missing SQLite3 library v3.4.2 or greater])])

	CPPFLAGS=$tmp_CPPFLAGS
	LIBS=$tmp_LIBS

	AC_SUBST(SQLITE3_INCLUDES)
	AC_SUBST(SQLITE3_LIBS)
])
