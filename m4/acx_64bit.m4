AC_DEFUN([ACX_64BIT],[
	AC_ARG_ENABLE(
	        [64bit],
        	[AS_HELP_STRING([--enable-64bit],[enable 64-bit compiling @<:@disabled@:>@])],
	        [enable_64bit="${enableval}"],
	        [enable_64bit="no"])

	if test "x$enable_64bit" = "xyes"
	then
	        tmp_CFLAGS=$CFLAGS
	        CFLAGS="-m64"
		AC_CACHE_CHECK([if we can compile in 64-bit mode], [acx_cv_prog_cc_64bit],[
			acx_cv_prog_cc_64bit=no
		        AC_COMPILE_IFELSE([
				AC_LANG_PROGRAM([],[return sizeof(void*) == 8 ? 0 : 1;])
			], [
				acx_cv_prog_cc_64bit=yes
	                ])
		])

		if test "x$acx_cv_prog_cc_64bit" = xyes; then
			AC_MSG_CHECKING([if we can run 64-bit programs])
			AC_CACHE_VAL([acx_cv_sys_64bit],[
				acx_cv_sys_64bit=no
				AC_RUN_IFELSE([
					AC_LANG_PROGRAM([],[return sizeof(void*) == 8 ? 0 : 1;])
				], [
					AC_MSG_RESULT(yes)
					acx_cv_sys_64bit=yes
				],[
					AC_MSG_RESULT(no)
					AC_MSG_ERROR([Don't know how to compile in 64-bit mode.])
					CFLAGS=$tmp_CFLAGS
				],[
					AC_MSG_WARN([Cannot test, assuming 64-bit])
					acx_cv_sys_64bit=yes
				])
			])

			CXXFLAGS="-m64 $CXXFLAGS"
			LDFLAGS="-m64 $LDFLAGS"
			CFLAGS="-m64 $tmp_CFLAGS"
		else
			CFLAGS=$tmp_CFLAGS
		fi
	fi

])
