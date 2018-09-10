AC_DEFUN([ACX_OPENSSL_GOST],[
	AC_MSG_CHECKING(for OpenSSL GOST support)

	tmp_CPPFLAGS=$CPPFLAGS
	tmp_LIBS=$LIBS

	CPPFLAGS="$CPPFLAGS $CRYPTO_INCLUDES"
	LIBS="$CRYPTO_LIBS $LIBS"

	AC_LANG_PUSH([C])
	AC_CACHE_VAL([acx_cv_lib_openssl_gost_support],[
		acx_cv_lib_openssl_gost_support=no
		AC_RUN_IFELSE([
			AC_LANG_SOURCE([[
				#include <openssl/engine.h>
				#include <openssl/crypto.h>
				#include <openssl/opensslv.h>
				int main()
				{
					ENGINE* eg;
					const EVP_MD* EVP_GOST_34_11;

					/* Initialise OpenSSL */
					OpenSSL_add_all_algorithms();

					/* Load engines */
				#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
					ENGINE_load_builtin_engines();
				#else
					OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_ALL_BUILTIN | OPENSSL_INIT_LOAD_CONFIG, NULL);
				#endif

					/* Initialise the GOST engine */
					eg = ENGINE_by_id("gost");
					if (eg == NULL)
						return 1;
					if (ENGINE_init(eg) <= 0)
						return 1;

					/* better than digest_gost */
					EVP_GOST_34_11 = ENGINE_get_digest(eg, NID_id_GostR3411_94);
					if (EVP_GOST_34_11 == NULL)
						return 1;

					/* from the openssl.cnf */
					if (ENGINE_register_pkey_asn1_meths(eg) <= 0)
						return 1;
					if (ENGINE_ctrl_cmd_string(eg,
					    "CRYPT_PARAMS",
					    "id-Gost28147-89-CryptoPro-A-ParamSet",
					    0) <= 0)
						return 1;

					return 0;
				}
			]])
		],[
			AC_MSG_RESULT([Found GOST engine])
			acx_cv_lib_openssl_gost_support=yes
		],[
			AC_MSG_RESULT([Cannot find GOST engine])
			AC_MSG_ERROR([OpenSSL library has no GOST support])
		],[
			AC_MSG_WARN([Cannot test, assuming GOST engine])
			acx_cv_lib_openssl_gost_support=yes
		])
	])
	AC_LANG_POP([C])

	CPPFLAGS=$tmp_CPPFLAGS
	LIBS=$tmp_LIBS
])
