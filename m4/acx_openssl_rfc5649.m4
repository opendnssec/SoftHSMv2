AC_DEFUN([ACX_OPENSSL_RFC5649],[
	AC_MSG_CHECKING(for OpenSSL RFC5649 support)

	tmp_CPPFLAGS=$CPPFLAGS
	tmp_LIBS=$LIBS

	CPPFLAGS="$CPPFLAGS $CRYPTO_INCLUDES"
	LIBS="$LIBS $CRYPTO_LIBS"

	AC_LANG_PUSH([C])
	AC_LINK_IFELSE([
		AC_LANG_SOURCE([[
			#include <openssl/aes.h>
			int main()
			{
				AES_wrap_key_withpad(NULL, NULL, NULL, NULL, 0);
				return 1;
			}
		]])
	],[
		AC_MSG_RESULT([Found AES key wrap with pad])
		AC_DEFINE([HAVE_AES_KEY_WRAP_PAD], [1],
		          [Define if advanced AES key wrap with pad is supported])
	],[
		AC_MSG_RESULT([Cannot find AES key wrap with pad])
	])
	AC_LANG_POP([C])

	CPPFLAGS=$tmp_CPPFLAGS
	LIBS=$tmp_LIBS
])
