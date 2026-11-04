AC_DEFUN([ACX_OPENSSL_FALCON],[
	AC_MSG_CHECKING(for OpenSSL Falcon-512 and Falcon-1024 support)

	tmp_CPPFLAGS=$CPPFLAGS
	tmp_LIBS=$LIBS

	CPPFLAGS="$CPPFLAGS $CRYPTO_INCLUDES"
	LIBS="$CRYPTO_LIBS $LIBS"

	AC_LANG_PUSH([C])
	AC_CACHE_VAL([acx_cv_lib_openssl_falcon_support],[
		acx_cv_lib_openssl_falcon_support=no
		AC_RUN_IFELSE([
			AC_LANG_SOURCE([[
				#include <openssl/evp.h>
				int main()
				{
					const char *names[] = { "falcon512", "falcon1024" };
					unsigned int i;
					for (i = 0; i < sizeof(names) / sizeof(names[0]); i++)
					{
						EVP_PKEY_CTX *pctx =
							EVP_PKEY_CTX_new_from_name(NULL, names[i], NULL);
						if (pctx == NULL)
							return 1;
						EVP_PKEY_CTX_free(pctx);
					}
					return 0;
				}
			]])
		],[
			AC_MSG_RESULT([yes])
			acx_cv_lib_openssl_falcon_support=yes
		],[
			AC_MSG_RESULT([no])
			acx_cv_lib_openssl_falcon_support=no
		],[
			AC_MSG_WARN([Cannot run the Falcon probe while cross-compiling; set acx_cv_lib_openssl_falcon_support=yes only if target support is known])
			acx_cv_lib_openssl_falcon_support=no
		])
	])

	AC_LANG_POP([C])

	CPPFLAGS=$tmp_CPPFLAGS
	LIBS=$tmp_LIBS
	have_lib_openssl_falcon_support="${acx_cv_lib_openssl_falcon_support}"
])
