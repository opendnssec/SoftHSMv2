AC_DEFUN([ACX_OPENSSL_SHA3],[
	AC_MSG_CHECKING(for OpenSSL SHA-3 support)

	tmp_CPPFLAGS=$CPPFLAGS
	tmp_LIBS=$LIBS

	CPPFLAGS="$CPPFLAGS $CRYPTO_INCLUDES"
	LIBS="$CRYPTO_LIBS $LIBS"

	AC_LANG_PUSH([C])
	AC_RUN_IFELSE([
		AC_LANG_SOURCE([[
			#include <openssl/evp.h>
			int main()
			{
				EVP_MD *sha3_224, *sha3_256, *sha3_384, *sha3_512;

				sha3_224 = EVP_sha3_224();
				sha3_256 = EVP_sha3_256();
				sha3_384 = EVP_sha3_384();
				sha3_512 = EVP_sha3_512();
				
				if (sha3_224 == NULL || sha3_256 == NULL || sha3_384 == NULL || sha3_512 == NULL)
					return 1;
				return 0;
			}
		]])
	],[
		AC_MSG_RESULT([Found SHA-3])
	],[
		AC_MSG_RESULT([Cannot find SHA-3])
		AC_MSG_ERROR([OpenSSL library has no SHA-3 support])
	],[])
	AC_LANG_POP([C])

	CPPFLAGS=$tmp_CPPFLAGS
	LIBS=$tmp_LIBS
])
