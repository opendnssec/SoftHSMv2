AC_DEFUN([ACX_OPENSSL_XWING],[
	AC_MSG_CHECKING(for OpenSSL ML-KEM-768 and X25519 support)

	tmp_CPPFLAGS=$CPPFLAGS
	tmp_LIBS=$LIBS

	CPPFLAGS="$CPPFLAGS $CRYPTO_INCLUDES"
	LIBS="$CRYPTO_LIBS $LIBS"

	AC_LANG_PUSH([C])
	AC_CACHE_VAL([acx_cv_lib_openssl_xwing_support],[
		acx_cv_lib_openssl_xwing_support=no
		AC_RUN_IFELSE([
			AC_LANG_SOURCE([[
				#include <openssl/evp.h>
				#include <openssl/core_names.h>
				#if !defined(OSSL_PKEY_PARAM_ML_KEM_SEED) || !defined(OSSL_KEM_PARAM_IKME)
				#error "OpenSSL headers lack X-Wing parameter definitions"
				#endif
				int main()
				{
					EVP_PKEY_CTX *mlkem =
						EVP_PKEY_CTX_new_from_name(NULL, "ML-KEM-768", NULL);
					EVP_PKEY_CTX *x25519 =
						EVP_PKEY_CTX_new_from_name(NULL, "X25519", NULL);
					if (mlkem == NULL || x25519 == NULL)
					{
						EVP_PKEY_CTX_free(mlkem);
						EVP_PKEY_CTX_free(x25519);
						return 1;
					}
					EVP_PKEY_CTX_free(mlkem);
					EVP_PKEY_CTX_free(x25519);
					return 0;
				}
			]])
		],[
			AC_MSG_RESULT([yes])
			acx_cv_lib_openssl_xwing_support=yes
		],[
			AC_MSG_RESULT([no])
			acx_cv_lib_openssl_xwing_support=no
		],[
			AC_MSG_WARN([Cannot run the X-Wing probe while cross-compiling; set acx_cv_lib_openssl_xwing_support=yes only if target support is known])
			acx_cv_lib_openssl_xwing_support=no
		])
	])

	AC_LANG_POP([C])

	CPPFLAGS=$tmp_CPPFLAGS
	LIBS=$tmp_LIBS
	have_lib_openssl_xwing_support="${acx_cv_lib_openssl_xwing_support}"
])
