AC_DEFUN([ACX_BOTAN_RAWPSS],[
	AC_MSG_CHECKING(for Botan raw PSS support)

	tmp_CPPFLAGS=$CPPFLAGS
	tmp_LIBS=$LIBS

	CPPFLAGS="$CPPFLAGS $CRYPTO_INCLUDES"
	LIBS="$CRYPTO_LIBS $LIBS"

	AC_LANG_PUSH([C++])
	AC_CACHE_VAL([acx_cv_lib_botan_raw_pss_support],[
		acx_cv_lib_botan_raw_pss_support=no
		AC_COMPILE_IFELSE([
			AC_LANG_SOURCE([[
				#include <botan/botan.h>
				#include <botan/version.h>
				int main()
				{
					using namespace Botan;

#if BOTAN_VERSION_CODE >= BOTAN_VERSION_CODE_FOR(2,3,0)
					return 0;
#else
#error "Botan too old"
#endif
				}
			]])
		],[
			AC_MSG_RESULT([Found raw PSS])
			acx_cv_lib_botan_raw_pss_support=yes
		],[
			AC_MSG_RESULT([Cannot find raw PSS support, upgrade to Botan >= v2.3.0])
		])
	])
	AC_LANG_POP([C++])
	if test "x$acx_cv_lib_botan_raw_pss_support" = xyes; then
		AC_DEFINE([WITH_RAW_PSS], [1],
			[Compile with raw RSA PKCS PSS])
	fi

	CPPFLAGS=$tmp_CPPFLAGS
	LIBS=$tmp_LIBS
])
