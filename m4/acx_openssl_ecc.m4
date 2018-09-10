AC_DEFUN([ACX_OPENSSL_ECC],[
	AC_MSG_CHECKING(for OpenSSL ECC support)

	tmp_CPPFLAGS=$CPPFLAGS
	tmp_LIBS=$LIBS

	CPPFLAGS="$CPPFLAGS $CRYPTO_INCLUDES"
	LIBS="$CRYPTO_LIBS $LIBS"

	AC_LANG_PUSH([C])
	AC_CACHE_VAL([acx_cv_lib_openssl_ecc_support],[
		acx_cv_lib_openssl_ecc_support=no
		AC_RUN_IFELSE([
			AC_LANG_SOURCE([[
				#include <openssl/ecdsa.h>
				#include <openssl/objects.h>
				int main()
				{
					EC_KEY *ec256, *ec384, *ec521;

					ec256 = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
					ec384 = EC_KEY_new_by_curve_name(NID_secp384r1);
					ec521 = EC_KEY_new_by_curve_name(NID_secp521r1);
					if (ec256 == NULL || ec384 == NULL || ec521 == NULL)
						return 1;
					return 0;
				}
			]])
		],[
			AC_MSG_RESULT([Found P256, P384, and P521])
			acx_cv_lib_openssl_ecc_support=yes
		],[
			AC_MSG_RESULT([Cannot find P256, P384, or P521])
			AC_MSG_ERROR([OpenSSL library has no ECC support])
		],[
			AC_MSG_WARN([Cannot test, assuming P256, P384, and P521])
			acx_cv_lib_openssl_ecc_support=yes
		])
	])
	AC_LANG_POP([C])

	CPPFLAGS=$tmp_CPPFLAGS
	LIBS=$tmp_LIBS
])
