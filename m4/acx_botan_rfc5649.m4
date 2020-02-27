AC_DEFUN([ACX_BOTAN_RFC5649],[
	AC_MSG_CHECKING(for Botan RFC5649 support)

	tmp_CPPFLAGS=$CPPFLAGS
	tmp_LIBS=$LIBS

	CPPFLAGS="$CPPFLAGS $CRYPTO_INCLUDES"
	LIBS="$CRYPTO_LIBS $LIBS"

	AC_DEFINE([HAVE_AES_KEY_WRAP], [1],
		  [Define if advanced AES key wrap without pad is supported])
	AC_LANG_PUSH([C++])
	AC_LINK_IFELSE([
		AC_LANG_SOURCE([[
			#include <botan/nist_keywrap.h>
			#include <botan/block_cipher.h>
			#include <botan/version.h>
			int main()
			{
				using namespace Botan;
				std::unique_ptr<BlockCipher> aes = BlockCipher::create_or_throw("AES-128");
				aes->set_key(std::vector<uint8_t>(16));
				uint8_t input[4] = { 1,2,3,4 };
				std::vector<uint8_t> wrapped = nist_key_wrap_padded(input, sizeof(input), *aes);
				return 1;
			}
		]])
	],[
		AC_MSG_RESULT([Found AES key wrap with pad])
		AC_DEFINE([HAVE_AES_KEY_WRAP_PAD], [1],
			  [Define if advanced AES key wrap with pad is supported])
	],[
		AC_MSG_RESULT([Cannot find AES key wrap with pad])

	])
	AC_LANG_POP([C++])

	CPPFLAGS=$tmp_CPPFLAGS
	LIBS=$tmp_LIBS
])
