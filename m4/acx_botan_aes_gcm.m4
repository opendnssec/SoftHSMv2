AC_DEFUN([ACX_BOTAN_AES_GCM],[
	AC_MSG_CHECKING(for Botan AES GCM support)

	tmp_CPPFLAGS=$CPPFLAGS
	tmp_LIBS=$LIBS

	CPPFLAGS="$CPPFLAGS $CRYPTO_INCLUDES"
	LIBS="$CRYPTO_LIBS $LIBS"

	AC_LANG_PUSH([C++])
	AC_RUN_IFELSE([
		AC_LANG_SOURCE([[
			#include <botan/botan.h>
			#include <botan/version.h>
			int main()
			{
				using namespace Botan;

#if BOTAN_VERSION_CODE >= BOTAN_VERSION_CODE_FOR(2,0,0)
				return 0;
#endif
				return 1;
			}
		]])
	],[
		AC_MSG_RESULT([Found AES GCM])
		AC_DEFINE([WITH_AES_GCM], [1],
			  [Compile with AES GCM])
	],[
		AC_MSG_RESULT([Cannot find AES GCM support, upgrade to Botan >= v2.0.0])

	])
	AC_LANG_POP([C++])

	CPPFLAGS=$tmp_CPPFLAGS
	LIBS=$tmp_LIBS
])
