AC_DEFUN([ACX_OPENSSL_ECC],[
	AC_MSG_CHECKING(for OpenSSL ECC support)

	tmp_CPPFLAGS=$CPPFLAGS
	tmp_LIBS=$LIBS

	CPPFLAGS="$CPPFLAGS $CRYPTO_INCLUDES"
	LIBS="$CRYPTO_LIBS $LIBS"

	AC_LANG_PUSH([C])
	AC_RUN_IFELSE([
		AC_LANG_SOURCE([[
			#include <openssl/ecdsa.h>
			#include <openssl/objects.h>
			int main()
			{
				EC_KEY *ec256, *ec384;

				ec256 = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
				ec384 = EC_KEY_new_by_curve_name(NID_secp384r1);
				if (ec256 == NULL || ec384 == NULL)
					return 1;
				return 0;
			}
		]])
	],[
		AC_MSG_RESULT([Found P256 and P384])
	],[
		AC_MSG_RESULT([Cannot find P256 or P384])
		AC_MSG_ERROR([OpenSSL library has no ECC support])
	],[])
	AC_LANG_POP([C])

	CPPFLAGS=$tmp_CPPFLAGS
	LIBS=$tmp_LIBS
])
