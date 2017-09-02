AC_DEFUN([ACX_BOTAN_SHA3],[
	AC_MSG_CHECKING(for Botan SHA-3 support)

	tmp_CPPFLAGS=$CPPFLAGS
	tmp_LIBS=$LIBS

	CPPFLAGS="$CPPFLAGS $CRYPTO_INCLUDES"
	LIBS="$CRYPTO_LIBS $LIBS"

	AC_LANG_PUSH([C++])
	AC_RUN_IFELSE([
		AC_LANG_SOURCE([[
			#include <botan/sha3.h>
			int main()
			{
				try {
					Botan::HashFunction* sha3 = new Botan::SHA_3(256);
				} catch(...) {
					return 1;
				}
				return 0;
			}
		]])
	],[
		AC_MSG_RESULT([Found SHA-3])
	],[
		AC_MSG_RESULT([Cannot find SHA-3])
		AC_MSG_ERROR([
Botan library has no valid SHA-3 support. Please upgrade to a later version
of Botan.
Alternatively disable SHA-3 support in SoftHSM with --disable-sha3
])
	],[])
	AC_LANG_POP([C++])

	CPPFLAGS=$tmp_CPPFLAGS
	LIBS=$tmp_LIBS
])
