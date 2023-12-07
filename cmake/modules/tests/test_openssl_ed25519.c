#include <openssl/evp.h>
#include <openssl/objects.h>
int main()
{
	EVP_PKEY_CTX *ctx;

	ctx = EVP_PKEY_CTX_new_id(NID_ED25519, NULL);
	if (ctx == NULL)
		return 1;
	return 0;
}
