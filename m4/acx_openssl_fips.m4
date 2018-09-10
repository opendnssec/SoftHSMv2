AC_DEFUN([ACX_OPENSSL_FIPS],[
	AC_MSG_CHECKING(for OpenSSL FIPS capable library)

	tmp_CPPFLAGS=$CPPFLAGS
	tmp_LIBS=$LIBS

	CPPFLAGS="$CPPFLAGS $CRYPTO_INCLUDES"
	LIBS="$CRYPTO_LIBS $LIBS"

	# check whether we can build an application which can
	# "reference the OpenSSL FIPS object module"

	AC_LANG_PUSH([C])
	AC_CACHE_VAL([acx_cv_lib_openssl_fips],[
		acx_cv_lib_openssl_fips=no
		AC_RUN_IFELSE([
			AC_LANG_SOURCE([[
				#include <openssl/crypto.h>
				int main()
				{
					return !FIPS_mode_set(1);
				}
			]])
		],[
			AC_MSG_RESULT([Found working FIPS_mode_set()])
			acx_cv_lib_openssl_fips=yes
		],[
			AC_MSG_RESULT([FIPS_mode_set(1) failed])
			AC_MSG_ERROR([OpenSSL library is not FIPS capable])
		],[
			AC_MSG_WARN([Cannot test, assuming FIPS])
			acx_cv_lib_openssl_fips=yes
		])
	])
	AC_LANG_POP([C])

	# build missing fips_premain_dso tool

	if test "x${FIPSLD_CC}" != "x"; then
		THERE="`echo $CC | sed -e 's|[[^/]]*$||'`"..
		if test "x${FIPSLIBDIR}" != "x"; then
			PREMAIN_C="${FIPSLIBDIR}/fips_premain.c"
		elif test -f "${THERE}/fips/fips_premain.c"; then
			PREMAIN_C="${THERE}/fips/fips_premain.c"
		elif test -f "${THERE}/lib/fips_premain.c"; then
			PREMAIN_C="${THERE}/lib/fips_premain.c"
		else
			AC_MSG_WARN([can't find fips_premain.c])
		fi

		$FIPSLD_CC $CPPFLAGS -DFINGERPRINT_PREMAIN_DSO_LOAD \
		-o src/lib/fips_premain_dso $PREMAIN_C $LIBS
	fi

	CPPFLAGS=$tmp_CPPFLAGS
	LIBS=$tmp_LIBS
])
