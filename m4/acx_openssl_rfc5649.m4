AC_DEFUN([ACX_OPENSSL_EVPAESWRAP],[
	AC_MSG_CHECKING(OpenSSL EVP interface for AES key wrapping)

	tmp_CPPFLAGS=$CPPFLAGS
	tmp_LIBS=$LIBS

	CPPFLAGS="$CPPFLAGS $CRYPTO_INCLUDES"
	LIBS="$CRYPTO_LIBS $LIBS"

	AC_LANG_PUSH([C])

	AC_LINK_IFELSE([
		AC_LANG_SOURCE([[
			#include <openssl/evp.h>
			int main()
			{
				EVP_aes_128_wrap();
				return 1;
			}
		]])
	],[
		AC_MSG_RESULT([RFC 3394 is supported])
		AC_DEFINE([HAVE_AES_KEY_WRAP], [1],
		          [Define if advanced AES key wrap without pad is supported in EVP interface])
	],[
		AC_MSG_RESULT([RFC 3394 is not supported])
	])

	AC_MSG_CHECKING(OpenSSL EVP interface for AES key wrapping with pad)
	AC_LINK_IFELSE([
		AC_LANG_SOURCE([[
			#include <openssl/evp.h>
			int main()
			{
				EVP_aes_128_wrap_pad();
				return 1;
			}
		]])
	],[
		AC_MSG_RESULT([RFC 5649 is supported])
		AC_DEFINE([HAVE_AES_KEY_WRAP_PAD], [1],
		          [Define if advanced AES key wrap with pad is supported in EVP interface])
	],[
		AC_MSG_RESULT([RFC 5649 is not supported])
	])

	AC_LANG_POP([C])

	CPPFLAGS=$tmp_CPPFLAGS
	LIBS=$tmp_LIBS
])
