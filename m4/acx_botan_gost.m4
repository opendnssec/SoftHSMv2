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
				#include <botan/init.h>
				#include <botan/gost_3410.h>
				#include <botan/oids.h>
				#include <botan/version.h>
				int main()
				{
					Botan::LibraryInitializer::initialize();
					const std::string name("gost_256A");
					const Botan::OID oid(Botan::OIDS::lookup(name));
					const Botan::EC_Group ecg(oid);
					try {
#if BOTAN_VERSION_CODE >= BOTAN_VERSION_CODE_FOR(1,11,0)
						const std::vector<Botan::byte> der =
						    ecg.DER_encode(Botan::EC_DOMPAR_ENC_OID);
#else
						const Botan::SecureVector<Botan::byte> der =
						    ecg.DER_encode(Botan::EC_DOMPAR_ENC_OID);
#endif
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
			AC_MSG_ERROR([
Botan library has no valid GOST support. Please upgrade to a later version
of Botan, above or including version 1.10.6 or 1.11.5.
Alternatively disable GOST support in SoftHSM with --disable-gost
])
		],[
			AC_MSG_WARN([Cannot test, assuming GOST])
			acx_cv_lib_botan_gost_support=yes
		])
	])
	AC_LANG_POP([C++])

	CPPFLAGS=$tmp_CPPFLAGS
	LIBS=$tmp_LIBS
])
