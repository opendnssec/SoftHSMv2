AC_DEFUN([ACX_BOTAN_GOST],[
	AC_MSG_CHECKING(for Botan GOST support)

	tmp_CPPFLAGS=$CPPFLAGS
	tmp_LIBS=$LIBS

	CPPFLAGS="$CPPFLAGS $CRYPTO_INCLUDES"
	LIBS="$CRYPTO_LIBS $LIBS"

	AC_LANG_PUSH([C++])
	AC_CACHE_VAL([acx_cv_lib_botan_gost_support],[
		acx_cv_lib_botan_gost_support=no
		AC_RUN_IFELSE([
			AC_LANG_SOURCE([[
				#include <botan/gost_3410.h>
				#include <botan/oids.h>
				#include <botan/version.h>
				int main()
				{
					const std::string name("gost_256A");
					const Botan::OID oid(Botan::OIDS::lookup(name));
					const Botan::EC_Group ecg(oid);
					try {
						const std::vector<Botan::byte> der =
						    ecg.DER_encode(Botan::EC_DOMPAR_ENC_OID);
					} catch(...) {
						return 1;
					}

					return 0;
				}
			]])
		],[
			AC_MSG_RESULT([Found GOST])
			acx_cv_lib_botan_gost_support=yes
		],[
			AC_MSG_RESULT([Cannot find GOST])
			acx_cv_lib_botan_gost_support=no
		],[
			AC_MSG_WARN([Cannot test, assuming GOST])
			acx_cv_lib_botan_gost_support=yes
		])
	])
	AC_LANG_POP([C++])

	CPPFLAGS=$tmp_CPPFLAGS
	LIBS=$tmp_LIBS
	have_lib_botan_gost_support="${acx_cv_lib_botan_gost_support}"
])
