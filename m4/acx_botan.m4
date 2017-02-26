AC_DEFUN([ACX_BOTAN],[
	AC_ARG_WITH(botan,
        	AC_HELP_STRING([--with-botan=PATH],[Specify prefix of path of Botan]),
		[
			BOTAN_PATH="$withval"
		],
		[
			BOTAN_PATH="/usr/local"
		])

	BOTAN_VERSION_MAJOR=2
	BOTAN_VERSION_MINOR=0
	AC_CHECK_FILE($BOTAN_PATH/include/botan-2/botan/version.h,
		      BOTAN_VERSION_MAJOR=2
		      BOTAN_VERSION_MINOR=0,
		      AC_CHECK_FILE($BOTAN_PATH/include/botan-1.11/botan/version.h,
				    BOTAN_VERSION_MAJOR=1
				    BOTAN_VERSION_MINOR=11,
				    AC_CHECK_FILE($BOTAN_PATH/include/botan-1.10/botan/version.h,
						  BOTAN_VERSION_MAJOR=1
						  BOTAN_VERSION_MINOR=10,
						  AC_MSG_ERROR([Cannot find Botan includes]))))
	AC_MSG_CHECKING(what are the Botan includes)
	if test "x${BOTAN_VERSION_MAJOR}" = "x2"; then
		BOTAN_INCLUDES="-I$BOTAN_PATH/include/botan-2"
	else
		BOTAN_INCLUDES="-I$BOTAN_PATH/include/botan-1.$BOTAN_VERSION_MINOR"
	fi
	AC_MSG_RESULT($BOTAN_INCLUDES)

	AC_MSG_CHECKING(what are the Botan libs)
	if test "x${BOTAN_VERSION_MAJOR}" = "x2"; then
		BOTAN_LIBS="-L$BOTAN_PATH/lib -lbotan-2"
	else
		BOTAN_LIBS="-L$BOTAN_PATH/lib -lbotan-1.$BOTAN_VERSION_MINOR"
	fi
	AC_MSG_RESULT($BOTAN_LIBS)

	if test "x${BOTAN_VERSION_MAJOR}" != "x1" -o "x${BOTAN_VERSION_MINOR}" != "x10"; then
		AX_CXX_COMPILE_STDCXX_11([noext],[mandatory])
	fi

	tmp_CPPFLAGS=$CPPFLAGS
	tmp_LIBS=$LIBS

	CPPFLAGS="$CPPFLAGS $BOTAN_INCLUDES"
	LIBS="$LIBS $BOTAN_LIBS"

	AC_LANG_PUSH([C++])
	AC_LINK_IFELSE(
		[AC_LANG_PROGRAM(
			[#include <botan/init.h>
			#include <botan/version.h>],
			[using namespace Botan;
			LibraryInitializer::initialize();
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
	AC_SUBST(BOTAN_VERSION_MAJOR)
	AC_SUBST(BOTAN_VERSION_MINOR)
])
