AC_DEFUN([ACX_64BIT],[
	AC_ARG_ENABLE(
	        [64bit],
        	[AS_HELP_STRING([--enable-64bit],[enable 64-bit compiling @<:@disabled@:>@])],
	        [enable_64bit="${enableval}"],
	        [enable_64bit="no"])

	if test "x$enable_64bit" = "xyes"
	then
	        AC_MSG_CHECKING(if we can compile in 64-bit mode)
	        tmp_CFLAGS=$CFLAGS
	        CFLAGS="-m64"
	        AC_RUN_IFELSE(
	                [
				AC_LANG_PROGRAM([],[return sizeof(void*) == 8 ? 0 : 1;])
			], [
	                        AC_MSG_RESULT(yes)
	                        CXXFLAGS="-m64 $CXXFLAGS"
	                        LDFLAGS="-m64 $LDFLAGS"
	                        CFLAGS="-m64 $tmp_CFLAGS"
	                ],[
	                        AC_MSG_RESULT(no)
	                        AC_MSG_ERROR([Don't know how to compile in 64-bit mode.])
	        		CFLAGS=$tmp_CFLAGS
	                ]
	        )
	fi

])
