AC_DEFUN([ACX_BOTAN_EDDSA],[
	AC_MSG_CHECKING(for Botan EDDSA support)

	tmp_CPPFLAGS=$CPPFLAGS
	tmp_LIBS=$LIBS

	CPPFLAGS="$CPPFLAGS $CRYPTO_INCLUDES"
	LIBS="$CRYPTO_LIBS $LIBS"

	AC_LANG_PUSH([C++])
	AC_CACHE_VAL([acx_cv_lib_botan_eddsa_support],[
		acx_cv_lib_botan_eddsa_support=no
		AC_RUN_IFELSE([
			AC_LANG_SOURCE([[
				#include <botan/init.h>
				#include <botan/ed25519.h>
				#include <botan/version.h>
				int main()
				{
					Botan::secure_vector<uint8_t> k(32);
					try {
						Botan::Ed25519_PrivateKey* key =
						new Botan::Ed25519_PrivateKey(k);
					} catch(...) {
						return 1;
					}
					return 0;
				}
			]])
		],[
			AC_MSG_RESULT([Found Ed25519])
			acx_cv_lib_botan_eddsa_support=yes
		],[
			AC_MSG_RESULT([Cannot find Ed25519])
			AC_MSG_ERROR([
Botan library has no valid EDDSA support. Please upgrade to a later version
of Botan with EDDSA support.
Alternatively disable EDDSA support in SoftHSM with --disable-eddsa
])
		],[
			AC_MSG_WARN([Cannot test, assuming EDDSA])
			acx_cv_lib_botan_eddsa_support=yes
		])
	])
	AC_LANG_POP([C++])

	CPPFLAGS=$tmp_CPPFLAGS
	LIBS=$tmp_LIBS
])
