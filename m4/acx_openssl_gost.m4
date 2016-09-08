AC_DEFUN([ACX_OPENSSL_GOST],[
	AC_MSG_CHECKING(for OpenSSL GOST support)

	tmp_CPPFLAGS=$CPPFLAGS
	tmp_LIBS=$LIBS

	CPPFLAGS="$CPPFLAGS $CRYPTO_INCLUDES"
	LIBS="$CRYPTO_LIBS $LIBS"

	AC_LANG_PUSH([C])
	AC_RUN_IFELSE([
		AC_LANG_SOURCE([[
			#include <openssl/conf.h>
			#include <openssl/engine.h>
			int main()
			{
				ENGINE *e;
				EC_KEY *ek;

				ek = NULL;
				OPENSSL_config(NULL);

				e = ENGINE_by_id("gost");
				if (e == NULL)
					return 1;
				if (ENGINE_init(e) <= 0)
					return 1;
				return 0;
			}
		]])
	],[
		AC_MSG_RESULT([Found GOST engine])
	],[
		AC_MSG_RESULT([Cannot GOST engine])
		AC_MSG_ERROR([OpenSSL library has no GOST support])
	],[])
	AC_LANG_POP([C])

	CPPFLAGS=$tmp_CPPFLAGS
	LIBS=$tmp_LIBS
])
