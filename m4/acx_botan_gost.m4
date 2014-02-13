AC_DEFUN([ACX_BOTAN_GOST],[
	AC_MSG_CHECKING(for Botan GOST support)

	tmp_CPPFLAGS=$CPPFLAGS
	tmp_LIBS=$LIBS

	CPPFLAGS="$CPPFLAGS $CRYPTO_INCLUDES"
	LIBS="$LIBS $CRYPTO_LIBS"

	AC_LANG_PUSH([C++])
	AC_RUN_IFELSE([
		AC_LANG_SOURCE([[
			#include <botan/init.h>
			#include <botan/gost_3410.h>
			#include <botan/oids.h>
			int main()
			{
				Botan::LibraryInitializer::initialize();
				const std::string name("gost_256A");
				const Botan::OID oid(Botan::OIDS::lookup(name));
				const Botan::EC_Group group(oid);
				return 0;
			}
		]])
	],[
		AC_MSG_RESULT([Found GOST])
	],[
		AC_MSG_RESULT([Cannot find GOST])
		AC_MSG_ERROR([Botan library has no GOST support])
	],[])
	AC_LANG_POP([C++])

	CPPFLAGS=$tmp_CPPFLAGS
	LIBS=$tmp_LIBS
])
