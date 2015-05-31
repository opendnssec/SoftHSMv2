AC_DEFUN([ACX_DESTRUCTOR],[
	AC_MSG_CHECKING(for destructor function attribute)

	AC_LANG_PUSH([C++])
	AC_LINK_IFELSE(
		[AC_LANG_PROGRAM(
			[int foo( void ) __attribute__((__destructor__));],
			[])],
		[AS_IF([test -s conftest.err],
			[AC_MSG_RESULT([no])],
			[AC_MSG_RESULT([yes])
			 AC_DEFINE(HAVE_FUNC_ATTRIBUTE_DESTRUCTOR,
				1, [Destructor function attribute])])],
		[AC_MSG_RESULT([no])]
	)
	AC_LANG_POP([C++])
])
