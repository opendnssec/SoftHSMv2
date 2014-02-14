AC_DEFUN([ACX_BOTAN_ECC],[
	AC_MSG_CHECKING(for Botan ECC support)

	tmp_CPPFLAGS=$CPPFLAGS
	tmp_LIBS=$LIBS

	CPPFLAGS="$CPPFLAGS $CRYPTO_INCLUDES"
	LIBS="$LIBS $CRYPTO_LIBS"

	AC_LANG_PUSH([C++])
	AC_RUN_IFELSE([
		AC_LANG_SOURCE([[
			#include <botan/init.h>
			#include <botan/ec_group.h>
			#include <botan/oids.h>
			int main()
			{
				Botan::LibraryInitializer::initialize();
				const std::string name("secp256r1");
				const Botan::OID oid(Botan::OIDS::lookup(name));
				const Botan::EC_Group ecg(oid);
				try {
#if BOTAN_VERSION_MINOR == 11
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
		AC_MSG_RESULT([Found P256])
	],[
		AC_MSG_RESULT([Cannot find P256])
		AC_MSG_ERROR([
Botan library has no valid ECC support. Please upgrade to a later version 
of Botan, above or including version 1.10.6 or 1.11.5.
Alternatively disable ECC support in SoftHSM with --disable-ecc
])
	],[])
	AC_LANG_POP([C++])

	CPPFLAGS=$tmp_CPPFLAGS
	LIBS=$tmp_LIBS
])
