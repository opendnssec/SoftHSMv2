AC_DEFUN([ACX_BOTAN],[
	AC_ARG_WITH(botan,
        	AC_HELP_STRING([--with-botan=PATH],[Specify prefix of path of Botan]),
		[
			BOTAN_PATH="$withval"
		],
		[
			BOTAN_PATH="/usr/local"
		])

	BOTAN_VERSION_MINOR=10
	AC_MSG_CHECKING(what are the Botan includes)
	AC_CHECK_FILE($BOTAN_PATH/include/botan-1.10/botan/init.h,
		      BOTAN_VERSION_MINOR=10,
		      AC_CHECK_FILE($BOTAN_PATH/include/botan-1.11/botan/init.h,
				    BOTAN_VERSION_MINOR=11,
				    AC_MSG_ERROR([Cannot find Botan includes])))
	BOTAN_INCLUDES="-I$BOTAN_PATH/include/botan-1.$BOTAN_VERSION_MINOR"
	AC_MSG_RESULT($BOTAN_INCLUDES)

	AC_MSG_CHECKING(what are the Botan libs)
	BOTAN_LIBS="-L$BOTAN_PATH/lib -lbotan-1.$BOTAN_VERSION_MINOR"
	AC_MSG_RESULT($BOTAN_LIBS)

	tmp_CPPFLAGS=$CPPFLAGS
	tmp_LIBS=$LIBS

	CPPFLAGS="$CPPFLAGS $BOTAN_INCLUDES"
	LIBS="$LIBS $BOTAN_LIBS"

	AC_LANG_PUSH([C++])
	AC_LINK_IFELSE(
		[AC_LANG_PROGRAM(
			[#include <botan/init.h>
			#include <botan/pipe.h>
			#include <botan/filters.h>
			#include <botan/hex.h>
			#include <botan/sha2_32.h>
			#include <botan/emsa3.h>
			#include <botan/version.h>],
			[using namespace Botan;
			LibraryInitializer::initialize();
			new EMSA3_Raw();
			#if BOTAN_VERSION_CODE < BOTAN_VERSION_CODE_FOR($1,$2,$3)
			#error "Botan version too old";
			#endif])],
		[AC_MSG_RESULT([checking for Botan >= v$1.$2.$3 ... yes])],
		[AC_MSG_RESULT([checking for Botan >= v$1.$2.$3 ... no])
		 AC_MSG_ERROR([Missing the correct version of the Botan library])]
	)
	AC_LANG_POP([C++])

	CPPFLAGS=$tmp_CPPFLAGS
	LIBS=$tmp_LIBS

	AC_SUBST(BOTAN_INCLUDES)
	AC_SUBST(BOTAN_LIBS)
	AC_SUBST(BOTAN_VERSION_MINOR)
])
