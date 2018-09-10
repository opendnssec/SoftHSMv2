AC_DEFUN([ACX_BOTAN_GNUMP],[
	tmp_CPPFLAGS=$CPPFLAGS
	tmp_LIBS=$LIBS

	CPPFLAGS="$CPPFLAGS $BOTAN_CFLAGS"
	LIBS="$LIBS $BOTAN_LIBS"

	AC_LANG_PUSH([C++])
	AC_LINK_IFELSE(
		[AC_LANG_PROGRAM(
			[#include <botan/build.h>],
			[#ifndef BOTAN_HAS_ENGINE_GNU_MP
			#error "No GNU MP support";
			#endif])],
		[AC_MSG_RESULT([checking for Botan GNU MP support... yes])],
		[AC_MSG_RESULT([checking for Botan GNU MP support... no])
		 AC_MSG_WARN([
====================================================
Botan has not been built with GNU MP (--with-gnump).
This will give negative impact on the performance.
====================================================])]
	)
	AC_LANG_POP([C++])

	CPPFLAGS=$tmp_CPPFLAGS
	LIBS=$tmp_LIBS
])
