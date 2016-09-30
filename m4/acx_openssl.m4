AC_DEFUN([ACX_OPENSSL],[
	AC_ARG_WITH(openssl,
        	AC_HELP_STRING([--with-openssl=PATH],[Specify prefix of path of OpenSSL]),
		[
			OPENSSL_PATH="$withval"
		],
		[
			OPENSSL_PATH="/usr/local"
		])

	AC_MSG_CHECKING(what are the OpenSSL includes)
	OPENSSL_INCLUDES="-I$OPENSSL_PATH/include"
	AC_MSG_RESULT($OPENSSL_INCLUDES)

	AC_MSG_CHECKING(what are the OpenSSL libs)
	OPENSSL_LIBS="-L$OPENSSL_PATH/lib -lcrypto"
	AC_MSG_RESULT($OPENSSL_LIBS)

	tmp_CPPFLAGS=$CPPFLAGS
	tmp_LIBS=$LIBS

	CPPFLAGS="$CPPFLAGS $OPENSSL_INCLUDES"
	LIBS="$LIBS $OPENSSL_LIBS"

	AC_CHECK_HEADERS([openssl/ssl.h],,[AC_MSG_ERROR([Can't find OpenSSL headers])])
	AC_CHECK_LIB(crypto, BN_new,,[AC_MSG_ERROR([Can't find OpenSSL library])])

	AC_MSG_CHECKING([for OpenSSL version])
	CHECK_OPENSSL_VERSION=m4_format(0x%02x%02x%02x000L, $1, $2, $3)
	AC_LANG_PUSH([C])
	AC_RUN_IFELSE([
		AC_LANG_SOURCE([[
			#include <openssl/ssl.h>
			#include <openssl/opensslv.h>
			int main()
			{
			#ifndef OPENSSL_VERSION_NUMBER
				return -1;
			#endif
			#if OPENSSL_VERSION_NUMBER >= $CHECK_OPENSSL_VERSION
				return 0;
			#else
				return 1;
			#endif
			}
		]])
	],[
		AC_MSG_RESULT([>= $1.$2.$3])
	],[
		AC_MSG_RESULT([< $1.$2.$3])
		AC_MSG_ERROR([OpenSSL library too old ($1.$2.$3 or later required)])
	],[])
	AC_LANG_POP([C])

	CPPFLAGS=$tmp_CPPFLAGS
	LIBS=$tmp_LIBS

	AC_SUBST(OPENSSL_INCLUDES)
	AC_SUBST(OPENSSL_LIBS)
])
